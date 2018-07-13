/*
 usage:
  launch ./demo in another terminal
  frida demo -l agent.js
 */

const ctor = new NativeFunction(Module.findExportByName(null, '_ZN4TimeC2Eiii'), 'pointer', ['pointer', 'int', 'int', 'int']);
const print = new NativeFunction(Module.findExportByName(null, '_ZNK4Time5printEv'), 'void', ['pointer']);
const instance = Memory.alloc(12);  // sizeof(Class)

ctor(instance, 12, 34, 56);  // initialize
print(instance); // call instance method

console.log('+0', Memory.readInt(instance));
console.log('+4', Memory.readInt(instance.add(4)));
console.log('+8', Memory.readInt(instance.add(8)));
