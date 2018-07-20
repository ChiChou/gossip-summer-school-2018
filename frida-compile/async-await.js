const openPtr = Module.findExportByName(null, 'open');

if (!openPtr)
  throw new Error('unsupported platform');

const open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
async function read(path) {
  const fd = open(Memory.allocUtf8String(path), 0);
  const stream = new UnixInputStream(fd, { autoClose: true });
  const bufferSize = 1024;
  let eof = false;
  let count = 0;

  while (!eof) {
    const buf = await stream.read(bufferSize);
    eof = (buf.byteLength && buf.byteLength < bufferSize);
    console.log('\ntrunk', count++);
    console.log(buf);
  }
}

read('/etc/passwd').catch(err => console.error(err, '\n', err.stack));