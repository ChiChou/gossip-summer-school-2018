#!/usr/bin/env python3

from typing import NamedTuple
from clang.cindex import Type, TypeKind, CursorKind,\
    Index, Config, TranslationUnit

# Config.set_library_path(
#     '/Applications/Xcode.app/Contents/' +
#     'Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib')

Config.set_library_path('/usr/local/opt/llvm/lib')


from pathlib import Path

GCC_BLACK_LIST = ('__builtin_constant_p', '__swbuf',
                  '__builtin_bswap32', '__builtin_bswap64')


def resolve_type(cursor):
    if cursor.type.get_pointee().kind != TypeKind.INVALID:
        return 'pointer'

    kind = cursor.type.kind
    if kind == TypeKind.TYPEDEF:
        kind = cursor.type.get_canonical().kind

    FRIDA_NATIVE_TYPES = {
        TypeKind.VOID: 'void',
        TypeKind.POINTER: 'pointer',
        TypeKind.INT: 'int',
        TypeKind.UINT: 'uint',
        TypeKind.LONG: 'long',
        TypeKind.ULONG: 'ulong',
        TypeKind.CHAR_S: 'char',
        TypeKind.CHAR_U: 'uchar',
        TypeKind.FLOAT: 'float',
        TypeKind.DOUBLE: 'double',
        TypeKind.SHORT: 'int16',
        TypeKind.USHORT: 'uint16',

        # int8_t resolved to CHAR_S
        # others? to be checked

        TypeKind.LONGLONG: 'unt64',
        TypeKind.ULONGLONG: 'uint64',
    }

    try:
        return FRIDA_NATIVE_TYPES[kind]
    except KeyError:
        raise NotImplementedError('%s is not supported yet' % kind)


class CodeGen(object):
    def __init__(self, source):
        opt = TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD

        self.filename = Path(source)
        self.index = Index.create()
        self.translation = self.index.parse(source, options=opt)
        self.printed_functions = set()

        self.define_map = {}

    def run(self):
        self.preprocess()
        self.visit(self.translation.cursor, self.pass_1)
        self.visit(self.translation.cursor, self.pass_2)

    def is_main(self, cursor):
        return cursor.location.file and \
            Path(cursor.location.file.name).absolute() == \
            self.filename.absolute()

    def preprocess(self):
        self.tokens = {token.spelling for token in \
            self.translation.cursor.get_tokens()}

    def is_valid_file(self, cursor):
        return cursor.location.file and \
            Path(cursor.location.file.name).absolute() == \
            self.filename.absolute()

    def pass_1(self, cursor, depth):
        # find all #define CONSTANT 0x0
        # unable to handle recursive macro or some type alias
        if cursor.kind == CursorKind.MACRO_DEFINITION:
            tokens = [token.spelling for token in cursor.get_tokens()]
            if len(tokens) == 2:
                key, val = tokens
                if key not in ('true', 'false'):
                    self.define_map[key] = val

    def pass_2(self, cursor, depth):
        if cursor.kind == CursorKind.CALL_EXPR:
            if cursor.type.kind == TypeKind.ELABORATED:
                self.print_struct_init(cursor)
            else:
                self.print_function_decl(cursor)

        if cursor.kind == CursorKind.MACRO_INSTANTIATION and \
                self.is_valid_file(cursor) and \
                cursor.spelling in self.define_map:
            key = cursor.spelling
            val = self.define_map[key]
            dependencies = [(key, val)]

            key = val
            while key in self.define_map:
                val = self.define_map[key]
                dependencies.insert(0, (key, val))
                key = val

            for key, val in dependencies:
                print(f'''const {key} = {val};''')


    def print_function_decl(self, cursor):
        # defined in same source file
        if cursor.get_definition():
            return

        name = cursor.displayname
        if name in self.printed_functions:
            return

        # blacklisted
        if name in GCC_BLACK_LIST:
            return

        self.printed_functions.add(name)
        suggestion = {
            'NSLog': 'console.log()',
            'printf': 'console.log()',
            'fprintf': 'console.log() or OutputStream',
            'puts': 'console.log()',
            'malloc': 'Memory.alloc()',
            'calloc': 'Memory.alloc(); Memory.writeByteArray()',
            '_dyld_image_count': 'Process.enumerateModulesSync().length',
            '_dyld_get_image_name':
                'Process.enumerateModulesSync()[index].name',
            '_dyld_get_image_header':
                'Process.enumerateModulesSync()[index].base',
        }

        if name in suggestion:
            print(f'''/* [info] function {name} detected,'''
                  f''' try `{suggestion[name]}` */''')
            return

        return_type = resolve_type(cursor)
        arg_types = ', '.join(['\'%s\'' % resolve_type(arg)
                               for arg in cursor.get_arguments()])
        print(f'''const {name} = new NativeFunction(Module.findExportByName('''
              f'''null, '{name}'), '{return_type}', [{arg_types}]);''')

    def print_struct_init(self, cursor):
        size = cursor.type.get_size()
        name = cursor.displayname
        print(f'''const struct_{name} = Memory.alloc({size});''')

    def visit(self, cursor, visitor, depth=0):
        visitor(cursor, depth)
        for child in cursor.get_children():
            self.visit(child, visitor, depth + 1)


if __name__ == '__main__':
    CodeGen('sample/lsof.c').run()
