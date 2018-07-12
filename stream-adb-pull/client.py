#!/usr/bin/env python3

from __future__ import print_function

import codecs
import frida


class App(object):
    def __init__(self):
        self.fp = None
        self.index = 0
        self.trunk_size = 0

    def on_message(self, msg, data):
        payload = msg['payload']
        event_type = payload['type']
        if event_type == 'begin':
            self.fp = open(payload['name'], 'wb')
            self.trunk_size = payload['trunk']
            self.index = -1

        elif event_type == 'end':
            self.fp.close()

        elif event_type == 'trunk':
            self.index += 1
            index = payload['index']
            assert index == self.index, 'invalid block index %d' % index
            self.fp.write(data)

        else:
            print('[+]', msg)

    def main(self):
        dev = frida.get_usb_device()
        app = dev.get_frontmost_application()
        assert app, 'no app running'

        print('target: %s (%d)' % (app.name, app.pid))
        with codecs.open('agent.js', 'r', 'utf-8') as fp:
            source = fp.read()

        session = dev.attach(app.pid)
        session.enable_jit()

        print('prepare injection')
        script = session.create_script(source)
        script.on('message', self.on_message)
        script.load()
        script.exports.download('boot-framework.oat')
        session.detach()
        print('bye')

if __name__ == '__main__':
    App().main()