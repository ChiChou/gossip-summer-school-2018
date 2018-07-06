Interceptor.attach(Module.findExportByName('Ws2_32.dll', 'WSARecv'), {
  onEnter: function(args) {
    console.log('recv');

    const count = args[2];
    const wsaBuf = args[1];
    this.len = Memory.readULong(wsaBuf);
    this.buf = Memory.readPointer(wsaBuf.add(4));

    // console.log(this.buf, this.len);
  },
  onLeave: function() {
    console.log('recv');
    console.log(Memory.readByteArray(this.buf, this.len));
  }
});

Interceptor.attach(Module.findExportByName('Ws2_32.dll', 'WSAAccept'), {
  onEnter: function(args) {
    console.log('accept');
  }
});