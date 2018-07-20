const handler = new NativeCallback(function(sig) {
    console.log('signal:', sig);
}, 'void', ['int']);

const signal = new NativeFunction(Module.findExportByName(null, 'signal'), 'int', ['int', 'pointer']);
const SIGINT = 2;
const SIGQUIT = 3;
const SIGABRT = 6;
const SIGKILL = 9;
const SIGTERM = 15;

signal(SIGINT, handler);
signal(SIGQUIT, handler);
signal(SIGABRT, handler);
signal(SIGKILL, handler);
signal(SIGTERM, handler);

