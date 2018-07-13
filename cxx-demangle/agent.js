const BUF_LEN = 1024;
const buf = Memory.alloc(BUF_LEN);

if (Process.platform == 'windows') {
  function msvcDemangle(name) {
    if (!Process.findModuleByName('dbghelp.dll')) {
      const LoadLibrary = new NativeFunction(
        Module.findExportByName('kernel32.dll', 'LoadLibraryA'),
        'pointer', ['pointer']);
      LoadLibrary(Memory.allocAnsiString('dbghelp.dll'));
    }

    const UnDecorateSymbolName = new NativeFunction(
      Module.findExportByName('dbghelp.dll', 'UnDecorateSymbolName'),
      'uint32', ['pointer', 'pointer', 'uint32', 'uint32']);
    const mangled = Memory.allocAnsiString(name);
    const len = UnDecorateSymbolName(mangled, buf, BUF_LEN, 0);
    if (len > 0)
      return Memory.readCString(buf, len);

    throw new Error('UnDecorateSymbolName failed');
  }
} else {
  function getPtr() {
    // Module.findExportByName(null, '__cxa_demangle') does not work on Android
    const list = ['libc++.so', 'libc++abi.dylib', null];
    var p = null, i = 0;
    while (!p && i < list.length) {
      const name = list[i++];
      p = Module.findExportByName(name, '__cxa_demangle');
    }

    if (!p)
      throw new Error('unsupported platform: ' +
        Process.platform + ', arch: ' + Process.arch);

    return p;
  }

  const demangle = new NativeFunction(
    getPtr(),
    'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

  function cxaDemangle(name) {
    const len = Memory.alloc(Process.pointerSize);
    const status = Memory.alloc(Process.pointerSize);

    Memory.writeUInt(len, BUF_LEN);
    const mangled = Memory.allocUtf8String(name);
    demangle(mangled, buf, len, status);

    const statusValue = Memory.readUInt(status);
    if (statusValue == 0)
      return Memory.readUtf8String(buf);

    throw new Error('__cxa_demangle failed, status: ' + statusValue);
  }
}

(function main() {
  const mainModule = Process.enumerateModulesSync()[0].name;

  // Windows: frida explorer.exe -l agent.js
  if (Process.platform == 'windows')
    Module.enumerateExportsSync('msvcp_win.dll').forEach(function(item) {
      console.log(msvcDemangle(item.name));
    });

  // macOS: frida Finder -l agent.js
  // iOS: frida -U Safari -l agent.js
  else if (Process.platform.match(/^(darwin|linux)$/))
    Module.enumerateImportsSync(mainModule).filter(
      function(item) {
        return item.name.startsWith('_Z')
      }).forEach(function(item) {
      console.log(cxaDemangle(item.name));
    })

  else
    throw Error('unknown platform: ' + Process.platform);
})()