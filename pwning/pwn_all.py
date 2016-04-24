#!/usr/bin/env python
# encoding:utf-8

import platform
import commands
import json
import time
import sys
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


def pwn_one(aim):
    cmd = config['cmd'].format(id=aim)
    if platform.system() == 'Darwin':
        status, flag = run_with_retry('gtimeout %d %s' % (config['timeout'], cmd))
    else:
        status, flag = run_with_retry('timeout %d %s' % (config['timeout'], cmd))
    sys.stdout.write('(ID = %d) status: %d, flag: %s\n' % (aim, status, abstract(flag)))
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


def pwn(config):
    global aim
    os.chdir(config['script'])
    log('out.log', 'PWN start')
    for aim in config['ids']:
        if os.fork() == 0:
            pwn_one(aim)
            exit()
    for aim in config['ids']:
        os.wait()
    log('out.log', 'PWN stop')


if __name__ == '__main__':
    while True:
        round_time = time.time()
        print '=' * 50, time.asctime(), '=' * 50
        problems = json.load(open('config.json'))
        for config in problems:
            if os.fork() == 0:
                print 'PWN %s start' % config['script']
                pwn(config)
                print 'PWN %s stop' % config['script']
                exit()
            os.wait()
        while time.time() - round_time < 60:
            time.sleep(1)
