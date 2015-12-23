#!/usr/bin/env python

import os
import random
import string

print ''.join([random.choice(string.letters + string.digits) for i in xrange(32)])
