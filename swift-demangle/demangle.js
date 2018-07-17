/*
 * usage:
  frida -U Music -l demangle.js
*/

function getDemangler() {
  const dlopen = new NativeFunction(Module.findExportByName(null, 'dlopen'), 'pointer', ['pointer', 'int']);
  const handle = dlopen(Memory.allocUtf8String('/System/Library/PrivateFrameworks/Swift/libswiftDemangle.dylib'), 1);
  if (handle.isNull()) throw new Error('unable to load libswiftDemangle');
  const demangle = new NativeFunction(Module.findExportByName('libswiftDemangle.dylib', 'swift_demangle_getDemangledName'), 'uint', ['pointer', 'pointer', 'uint']);
  const size = 1024;
  const buf = Memory.alloc(size);

  return function(name) {
    const len = demangle(Memory.allocUtf8String(name), buf, size);
    if (!len) return null;
    return Memory.readUtf8String(buf, len);
  }
}

const demangle = getDemangler();

console.log('classes');
for (var key in ObjC.classes) {
  /*
    copied from
    https://github.com/apple/swift/blob/master/tools/swift-demangle/swift-demangle.cpp#L177
  */
  if (key.match(/(_T|_?\\$[Ss])[_a-zA-Z0-9$.]+/)) {
    const original = demangle(key);
    if (!original) {
      console.warn('faield to demangle name: ', key);
      continue;
    }
    console.log(key, '>>', original);
  }
}

console.log('emoji?');
console.log(demangle('_TF4testX4GrIhFTSiSi_Si'));
