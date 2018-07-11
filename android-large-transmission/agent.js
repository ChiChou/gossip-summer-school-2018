const O_RDONLY = 0;
const open = new NativeFunction(Module.findExportByName(null, 'open'),
  'int', ['pointer', 'int', 'int']);

rpc.exports = {
  download(fileName) {
    const { path } = Process.findModuleByName(fileName);
    const fd = open(Memory.allocUtf8String(path), O_RDONLY, 0);
    const stream = new UnixInputStream(fd, { autoClose: true });
    const watermark = 2 * 1024 * 1024; // 2M

    return new Promise((resolve, reject) => {
      let i = 0;
      const read = () => {
        stream.read(watermark).then((buffer) => {
          send({ type: 'trunk', index: i }, buffer);
          if (buffer.byteLength === watermark) {
            i++;
            setImmediate(read);
          } else {
            send({ type: 'end' });
            resolve();
          }
        }).catch(err => console.error('fatal:', err));
      };
      // todo: add size, metadata, etc
      send({ type: 'begin', trunk: watermark, name: fileName });
      setImmediate(read);
    });
  }
}
