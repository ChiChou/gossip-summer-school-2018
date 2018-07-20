const NSLog = new NativeFunction(Module.findExportByName('Foundation', 'NSLog'), 'void', ['pointer', '...', 'pointer']);
const format = ObjC.classes.NSString.stringWithString_('hello %@!');
const param = ObjC.classes.NSString.stringWithString_('world');
NSLog(format, param);
