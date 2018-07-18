# -*- coding: utf-8 -*-
from __future__ import print_function

import frida
import os


def user_input():
    prompt = 'please input something: '
    try:
        return raw_input(prompt)
    except:
        return input(prompt)


# attach to python interpreter process itself :)
session = frida.attach(os.getpid())
script = session.create_script("""\
'use strict';
rpc.exports = {
  hello: function () {
    return 'Hello';
  },
  failPlease: function () {
    // this exception may crash python
    throw new Error('failed to call rpc method');
  },
  wait: function() {
    return new Promise(function(resolve, reject) {
      setTimeout(function() {
        resolve('wait for me')
      }, 200)
    })
  }
};

// send a log to client
console.warn("alert");

// send JSON message and binary payload to client
send({
  topic: "greet",
  format: "json"
}, new Buffer("hello, world"));

setTimeout(function() {
  // this exception will only emit an event
  throw new Error('other exception');
}, 100);

setImmediate(function() {
  recv('input', function(msg) {
    console.log('>>> you have just input', msg.payload);
  }).wait();
});

""")

def on_message(msg, payload):
    print('msg', msg, payload)

    if msg.get('payload') and msg.get('payload').get('topic') == 'greet':
      script.post({ 'type': 'input', 'payload': user_input() })

def on_console_log(level, text):
    print('console.' + level + ':', text)

script.on('message', on_message)
script.set_log_handler(on_console_log)
script.load()
api = script.exports
print("api.hello() =>", api.hello())

try:
    api.fail_please()
except frida.core.RPCException as e:
    print('rpc error', e)

print('api.wait() =>', api.wait())
