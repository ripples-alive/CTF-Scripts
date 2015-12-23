#!/usr/bin/env python
# encoding:utf-8

import platform
import commands
import json
import time
import os

from common import *


def run_with_retry(cmd, max_retry=2):
    retry = 0
    while retry < max_retry:
        status, output = commands.getstatusoutput(cmd)
        if status == 0:
            break
        retry += 1
    return status, output


def pwn(config):
    global aim
    os.chdir(config['script'])
    log('out.log', 'PWN start')
    for aim in config['ids']:
        cmd = config['cmd'].format(id=aim)
        if platform.system() == 'Darwin':
            status, flag = run_with_retry('gtimeout %d %s' % (config['timeout'], cmd))
        else:
            status, flag = run_with_retry('timeout %d %s' % (config['timeout'], cmd))
        print '(ID = %d) status: %d, flag: %s' % (aim, status, abstract(flag))
        if status == 0:
            flag = flag.strip()
            result = submit_with_retry(flag)
            record_in_db({
                'id': aim,
                'service': config['service'],
                'flag': flag,
                'result': result
            })
            if result is True:
                log('out.log', '(ID = %d) %s' % (aim, flag))
            elif result is not False:
                log('error.log', '(ID = %d) %s => %s' % (aim, flag, result))
    log('out.log', 'PWN stop')


if __name__ == '__main__':
    while True:
        print '=' * 50, time.asctime(), '=' * 50
        problems = json.load(open('config.json'))
        for config in problems:
            if os.fork() == 0:
                print 'PWN %s start' % config['script']
                pwn(config)
                print 'PWN %s stop' % config['script']
                exit()
        time.sleep(60)
