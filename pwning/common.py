#!/usr/bin/env python
# coding:utf-8

import requests
import json
import time


# This function should be replaced.
def submit_flag(flag):
    """
    True => Success
    False => Duplicate
    others => error info
    """
    import random
    return random.choice([True, False, 'error info'])


def submit_with_retry(flag):
    retry = 0
    result = ''
    while retry < 3:
        try:
            result = submit_flag(flag)
            if type(result) is bool:
                return result
        except Exception, e:
            result = e.message
        retry += 1
        time.sleep(1)
    return result


def log(filename, msg):
    fp = open(filename, 'a')
    fp.write('[%s] %s\n' % (time.asctime(), str(msg).replace('\n', '; ')))
    fp.close()


def abstract(s, n=100):
    s = str(s)
    if len(s) <= n:
        return s
    return s[:n] + '...'


def record_in_db(info):
    # print 'Will record in database:', info
    pass
