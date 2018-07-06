function hook(suffix) {
  const symbol = 'xpc_connection_send_message' + suffix;
  Interceptor.attach(Module.findExportByName(null, symbol), {
    onEnter: function (args) {
      const conn = new ObjC.Object(args[0]);
      const msg = new ObjC.Object(args[1]);
      const lines = ['', symbol + ' >>>', conn, msg];
      if (suffix === '_with_reply') {
        const withReply = new ObjC.Block(args[3]);
        const original = withReply.implementation;
        const buf = lines.join('\n');
        withReply.implementation = function(reply) {
          console.log([buf, 'async reply <<<', reply].join('\n'));
          return original.call(this, reply);
        }
      }
      this.lines = lines;
    },
    onLeave(retVal) {
      const lines = this.lines;
      if (suffix === '_with_reply_sync') {
        lines.push('sync reply <<<');
        lines.push(new ObjC.Object(retVal));
      }
      if (suffix !== '_with_reply')
        console.log(lines.join('\n'));
    }
  })
}

hook('');
hook('_with_reply');
hook('_with_reply_sync');
