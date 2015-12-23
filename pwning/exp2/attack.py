#!/usr/bin/env python

import os
import time
import random
import string

time.sleep(random.random() * 2)
print ''.join([random.choice(string.letters + string.digits) for i in xrange(111)])
