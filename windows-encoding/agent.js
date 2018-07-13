/*
  usage: frida explorer.exe -l agent.js
 */

const FindWindow = new NativeFunction(Module.findExportByName('user32.dll', 'FindWindowA'), 'pointer', ['pointer', 'pointer']);
const GetWindowTextA = new NativeFunction(Module.findExportByName('user32.dll', 'GetWindowTextA'), 'int', ['pointer', 'pointer', 'int']);
const GetWindowTextW = new NativeFunction(Module.findExportByName('user32.dll', 'GetWindowTextW'), 'int', ['pointer', 'pointer', 'int']);

const hWnd = FindWindow(Memory.allocAnsiString('SystemTray_Main'), NULL);
if (hWnd.isNull())
  throw Error('Unable to find tray window. Does your desktop crash?');

const buf = Memory.alloc(1024);

GetWindowTextA(hWnd, buf, 1024);
console.log('ansi: ', Memory.readAnsiString(buf));
console.log('c string: ', Memory.readCString(buf));

GetWindowTextW(hWnd, buf, 1024);
console.log('unicode16: ', Memory.readUtf16String(buf));

// try utf8 may throw an exception: "can't decode XX at [location]"