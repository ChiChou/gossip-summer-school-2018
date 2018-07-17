/*
 usage:
  launch ./demo in another terminal
  frida demo -l agent.js
 */

const base = Process.enumerateModulesSync()[0].base;

const ctor = new NativeFunction(DebugSymbol.getFunctionByName('Cat::Cat(int, Color)'), 'pointer', ['pointer', 'int', 'int']);
const print = new NativeFunction(DebugSymbol.getFunctionByName('Cat::printDescription()'), 'void', ['pointer']);
const instance = Memory.alloc(16);  // sizeof(Cat)

ctor(instance, 3, 2);  // 3 year old orange cat
print(instance); // call instance method

const vtable = Memory.readPointer(instance);
console.log('relative addr:', vtable.sub(base));
console.log(DebugSymbol.fromAddress(vtable));

console.log('age', Memory.readInt(instance.add(8)));
console.log('weight', Memory.readInt(instance.add(12)));

Memory.writeInt(instance.add(8), 1);
// patched data
print(instance);
