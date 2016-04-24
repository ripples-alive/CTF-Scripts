#!/usr/bin/env python
# coding:utf-8

import SocketServer
import json

from common import *


class FlagHandler(SocketServer.StreamRequestHandler):

    def handle(self):
        content = self.rfile.read().strip().strip('\x00').replace('\n', '')
        ip = self.client_address[0]

        try:
            info = json.loads(content)
            assert info['flag'] is not None and info['service'] is not None
            info['flag'] = info['flag'].strip()
        except Exception, e:
            info = {'flag': content, 'service': None}
        if 'id' not in info:
            info['id'] = ip
        print '({0[id]}) service: {0[service]}, flag: {0[flag]}'.format(info)

        result = submit_with_retry(info['flag'])
        info['result'] = result
        record_in_db(info)

        if result is True:
            log('out.log', '(%s) %s' % (ip, content))
            self.wfile.write('Success')
        elif result is not False:
            log('error.log', '(%s) %s => %s' % (ip, content, result))
            self.wfile.write('Error: %r, Submit: %r' % (result, content))
        else:
            self.wfile.write('Duplicate')


if __name__ == '__main__':
    server = SocketServer.ThreadingTCPServer(('', 8888), FlagHandler)
    server.serve_forever()
