/*
 * works for both iOS and macOS
 *
 * example: sudo frida -l xpc-analyzer/incoming.js launchservicesd
 */

Interceptor.attach(DebugSymbol.getFunctionByName('_xpc_connection_call_event_handler'), {
  onEnter: function(args) {
    console.log('call event handler:')
    console.log(new ObjC.Object(args[0]));
    console.log(new ObjC.Object(args[1]));
  }
});

// todo: add NSXPCConnection