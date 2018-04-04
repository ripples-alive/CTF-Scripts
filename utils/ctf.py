#!/usr/bin/env python
# encoding:utf-8

import commands
import gzip
import os
import re
import weakref
from cStringIO import StringIO

import pwn
from pwn import *

__all__ = [
    'factor',
    'gcd',
    'ext_euclid',
    'rsa_decrypt',
    'unhex',
    'ljust',
    'rjust',
    'gzipc',
    'gzipd',
    'shellcode',
]

# export all imported from pwn
__all__ += [i for i in dir(pwn) if not i.startswith('__')]
__all__ = list(set(__all__))

#############################
### utils for calculation ###
#############################


def factor(n):
    """Integer factorization (Prime decomposition)."""
    while (2 < n) and (n & 1 == 0):
        n >>= 1
        print '2 * ',
    i = 3
    while i < n:
        if n % i == 0:
            n /= i
            print '%d *' % i,
            continue
        i += 2
    print n


def gcd(a, b):
    """Calculate greatest common divisor."""
    if b == 0:
        return a
    return gcd(b, a % b)


def ext_euclid(a, b):
    """Extended Euclidean algorithm. a > b, ax+by=GCD(a, b) => x,y"""
    if a % b == 0:
        return 0, 1
    x, y = ext_euclid(b, a % b)
    return y, x - a / b * y


def rsa_decrypt(c, e, p, q):
    """Decrypt RSA encrypted message when p and q are known."""
    # First calculate d.
    phi_n = (p - 1) * (q - 1)
    d, _ = ext_euclid(e, phi_n)
    d %= phi_n

    # Decrypt message using e.
    c_value = int(enhex(c), 16)
    n = p * q
    m = pow(c_value, d, n)
    m_hex = '%x' % m
    return unhex(m_hex)


#############################
### utils for EXP writing ###
#############################


def unhex(s):
    """Hex decode strings.
    Override unhex in pwntools.
    Hex-strings with odd length are acceptable.
    """
    s = str(s).strip()
    return (len(s) % 2 and '0' + s or s).decode('hex')


def ljust(s, n, c=None):
    assert len(s) <= n
    if c is None:
        return s + cyclic(n - len(s))
    else:
        return s.ljust(n, c)


def rjust(s, n, c=None):
    assert len(s) <= n
    if c is None:
        return cyclic(n - len(s)) + s
    else:
        return s.rjust(n, c)


def gzipc(s, compresslevel=9):
    io = StringIO()
    gp = gzip.GzipFile(mode='w', compresslevel=compresslevel, fileobj=io)
    gp.write(s)
    gp.close()
    io.seek(0)
    return io.read()


def gzipd(s):
    return gzip.GzipFile(fileobj=StringIO(s)).read()


###############################
### tmux related operations ###
###############################

INTERVAL = 0.1


def in_tmux():
    return 'TMUX' in os.environ


def tmux_get_pane_list():
    status, output = commands.getstatusoutput('tmux list-panes')
    if status != 0:
        error('failed: tmux list-panes\n%s', output)
        return

    pane_pattern = re.compile('^%\d+$')
    pane_list = []
    for line in output.split('\n'):
        for word in line.split()[::-1]:
            if pane_pattern.match(word):
                pane_list.append(word)
                break
    return pane_list


def tmux_find_new_pane(callback):
    pane_list = tmux_get_pane_list()
    ret = callback()
    while True:
        new_pane_list = tmux_get_pane_list()
        diff = set(new_pane_list) - set(pane_list)
        if diff:
            pane_id = diff.pop()
            log.debug('new pane id: %s', pane_id)
            return Tmux(pane_id), ret


class Tmux(object):

    def __init__(self, pane_id):
        self.pane_id = pane_id

    def send_keys(self, *args):
        for key in args:
            cmd = 'tmux send-keys -t {} "{}"'.format(self.pane_id, key)
            log.debug('command: %s', cmd)
            status, output = commands.getstatusoutput(cmd)
            if status != 0:
                error('failed: tmux send-keys\n%s', output)

    def sendline(self, data):
        self.send_keys(data, 'C-m')

    def capture(self, start=None, stop=None):
        cmd = 'tmux capture-pane -pt {}'.format(self.pane_id)
        if start is not None:
            cmd += ' -S {}'.format(start)
        if stop is not None:
            cmd += ' -E {}'.format(stop)
        log.debug('command: %s', cmd)
        status, output = commands.getstatusoutput(cmd)
        if status != 0:
            error('failed: tmux capture-pane\n%s', output)
        return output

    def get_last_line(self, count=1):
        output = self.capture()
        while True:
            time.sleep(INTERVAL)
            new_output = self.capture()
            if output == new_output:
                break
            output = new_output
        return '\n'.join(output.split('\n')[-count:])


#######################
### utils for debug ###
#######################


def _gdb_debug(arg, gdbscript=None, *args, **kwargs):

    def do_debug():
        return pwnlib.gdb._debug(arg, gdbscript=gdbscript, *args, **kwargs)

    if context.noptrace or not in_tmux():
        return do_debug()

    tmux, tube = tmux_find_new_pane(do_debug)
    while not tmux.capture(start=-1).strip():
        time.sleep(INTERVAL)
    tube.gdb = GDB(tmux)
    tube.gdb.detachable = False
    return tube


def _gdb_attach(target, gdbscript=None, *args, **kwargs):

    def do_attach():
        return pwnlib.gdb._attach(target, gdbscript=gdbscript, *args, **kwargs)

    if context.noptrace or not in_tmux():
        return do_attach()

    # if gdbscript is a file object, then read it; we probably need to run some
    # more gdb script anyway
    if isinstance(gdbscript, file):
        with gdbscript:
            gdbscript = gdbscript.read()
    gdbscript = gdbscript or ''
    gdbscript = 'set prompt {0} \n{1}'.format(
        term.text.bold_red('gdb$'), gdbscript)

    if not isinstance(target, pwnlib.tubes.tube.tube):
        return do_attach()

    if target.gdb.is_attached():
        log.warn('debugger is already attached, skip')
        return

    tmux, ret = tmux_find_new_pane(do_attach)
    target.gdb = GDB(tmux)
    return ret


class _FakeGDB(object):

    def __init__(self, tube):
        self._tube = weakref.ref(tube)

    def attach(self, *args, **kwargs):
        if context.noptrace:
            log.warn_once("Skipping debug attach since context.noptrace==True")
            return
        pwnlib.gdb.attach(self._tube(), *args, **kwargs)

    def __getattr__(self, key):
        return lambda *args, **kwargs: None


class GDB(object):

    def __init__(self, tmux):
        if not isinstance(tmux, Tmux):
            tmux = Tmux(tmux)
        self._tmux = tmux
        self._attached = True
        self._target_pid = self.get_pid()
        self.detachable = True

    def is_attached(self):
        return self._attached

    def is_running(self):
        if not self.is_attached():
            return False
        return 'gdb$' not in self.get_last_line()

    def is_paused(self):
        if not self.is_attached():
            return False
        return 'gdb$' in self.get_last_line()

    def attach(self, *args, **kwargs):
        if self._attached:
            return

        self.execute('attach {:d}'.format(self._target_pid))
        self._attached = True

    def detach(self):
        if not self._attached:
            return
        if not self.detachable:
            self.c()
            return

        self.execute('detach', 1)
        self._attached = False

    def interrupt(self):
        if not self.is_running():
            return

        self.send('C-c')
        while not self.is_paused():
            time.sleep(INTERVAL)

    def execute(self, cmd, output_line=1):
        is_paused = self.is_paused()
        if not is_paused:
            self.interrupt()
        self.sendline(cmd)
        output = self.get_last_line(output_line + 1)
        output = output.rsplit('\n', 1)[0]
        if not is_paused:
            self.c()
        return output

    def c(self):
        if not self.is_paused():
            return
        self.execute('c')

    def b(self, addr):
        if not self.is_attached():
            return

        if type(addr) == list or type(addr) == tuple:
            for one in addr:
                self.b(one)
        elif type(addr) == int or type(addr) == long:
            self.execute('b *0x{0:x}'.format(addr))
        else:
            self.execute('b {0}'.format(addr))

    def send(self, *data):
        self._tmux.send_keys(*data)

    def sendline(self, data):
        self.send(data, 'C-m')

    def get_last_line(self, count=1):
        return self._tmux.get_last_line(count=count)

    def get_pid(self):
        return int(self.execute('pid'))

    def get_base(self, name='code'):
        output = self.execute('{}base'.format(name))
        return int(output.rsplit(':', 1)[1], 0)


def _tube_init(self, *args, **kwargs):
    self._init(*args, **kwargs)
    self.gdb = _FakeGDB(self)


def _ext_interactive(self, prompt=term.text.bold_red('$') + ' '):
    """interactive(prompt = pwnlib.term.text.bold_red('$') + ' ')
    Does simultaneous reading and writing to the tube. In principle this just
    connects the tube to standard in and standard out, but in practice this
    is much more usable, since we are using :mod:`pwnlib.term` to print a
    floating prompt.
    Thus it only works in while in :data:`pwnlib.term.term_mode`.
    """

    self.info('Switching to interactive mode')

    go = threading.Event()

    def recv_thread():
        while not go.isSet():
            try:
                cur = self.recv(timeout=0.05)
                cur = cur.replace('\r\n', '\n')
                if cur:
                    sys.stdout.write(cur)
                    sys.stdout.flush()
            except EOFError:
                self.info('Got EOF while reading in interactive')
                break

    t = context.Thread(target=recv_thread)
    t.daemon = True
    t.start()

    try:
        while not go.isSet():
            if term.term_mode:
                data = term.readline.readline(prompt=prompt, float=True)
            else:
                data = sys.stdin.readline()

            if data:
                try:
                    data = safeeval.const(
                        '"""{0}"""'.format(data.replace('"', r'\"')))
                    self.send(data)
                except ValueError:
                    log.warning('Illegal input, ignored!')
                except EOFError:
                    go.set()
                    log.info('Got EOF while sending in interactive')
            else:
                go.set()
    except KeyboardInterrupt:
        log.info('Interrupted')
        go.set()

    while t.is_alive():
        t.join(timeout=0.1)


def _send(self, data):
    self._send(str(data))


def _sendline(self, data):
    self._sendline(str(data))


def _sendlines(self, data):
    for row in data:
        self.sendline(row)


def _recvregex(self, regex, exact=False, group=None, **kwargs):
    """recvregex(regex, exact = False, timeout = default) -> str
    Wrapper around :func:`recvpred`, which will return when a regex
    matches the string in the buffer.
    By default :func:`re.RegexObject.search` is used, but if `exact` is
    set to True, then :func:`re.RegexObject.match` will be used instead.
    If the request is not satisfied before ``timeout`` seconds pass,
    all data is buffered and an empty string (``''``) is returned.
    """

    if isinstance(regex, (str, unicode)):
        regex = re.compile(regex)

    if exact:
        pred = regex.match
    else:
        pred = regex.search

    data = self.recvpred(pred, **kwargs)
    if group is None:
        return data
    match = pred(data)
    if hasattr(group, '__iter__'):
        return match.group(*group)
    return match.group(group)


def _recvline_regex(self, regex, exact=False, group=None, **kwargs):
    """recvregex(regex, exact = False, keepends = False, timeout = default) -> str
    Wrapper around :func:`recvline_pred`, which will return when a regex
    matches a line.
    By default :func:`re.RegexObject.search` is used, but if `exact` is
    set to True, then :func:`re.RegexObject.match` will be used instead.
    If the request is not satisfied before ``timeout`` seconds pass,
    all data is buffered and an empty string (``''``) is returned.
    """

    if isinstance(regex, (str, unicode)):
        regex = re.compile(regex)

    if exact:
        pred = regex.match
    else:
        pred = regex.search

    data = self.recvline_pred(pred, **kwargs)
    if group is None:
        return data
    match = pred(data)
    if hasattr(group, '__iter__'):
        return match.group(*group)
    return match.group(group)


pwnlib.gdb._debug = pwnlib.gdb.debug
pwnlib.gdb.debug = _gdb_debug
pwnlib.gdb._attach = pwnlib.gdb.attach
pwnlib.gdb.attach = _gdb_attach

pwnlib.tubes.tube.tube._init = pwnlib.tubes.tube.tube.__init__
pwnlib.tubes.tube.tube.__init__ = _tube_init
pwnlib.tubes.tube.tube._interactive = pwnlib.tubes.tube.tube.interactive
pwnlib.tubes.tube.tube.interactive = _ext_interactive
pwnlib.tubes.tube.tube._send = pwnlib.tubes.tube.tube.send
pwnlib.tubes.tube.tube.send = _send
pwnlib.tubes.tube.tube._sendline = pwnlib.tubes.tube.tube.sendline
pwnlib.tubes.tube.tube.sendline = _sendline
pwnlib.tubes.tube.tube.sendlines = _sendlines
pwnlib.tubes.tube.tube._recvregex = pwnlib.tubes.tube.tube.recvregex
pwnlib.tubes.tube.tube.recvregex = _recvregex
pwnlib.tubes.tube.tube._recvline_regex = pwnlib.tubes.tube.tube.recvline_regex
pwnlib.tubes.tube.tube.recvline_regex = _recvline_regex

#################################
### a short shellcode for x86 ###
#################################

# // al -> sys_execve
# // bx -> filename
# // cx -> args
# // dx -> env
# // "\xb0\x0b"                  // mov    $0xb,%al
# "\x6a\x0b"                  // push   $0xb
# "\x58"                      // pop    %eax
# "\x99"                      // cltd
# "\x31\xc9"                  // xor    %ecx,%ecx
# "\x52"                      // push   %edx
# "\x68\x2f\x2f\x73\x68"      // push   $0x68732f2f
# "\x68\x2f\x62\x69\x6e"      // push   $0x6e69622f
# "\x89\xe3"                  // mov    %esp,%ebx
# "\xcd\x80"                  // int    $0x80
#
# "\x6a\x0b\x58\x99\x31\xc9\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
# "j\x0bX\x991\xc9Rh//shh/bin\x89\xe3\xcd\x80"
# "j\x0b""X\x99""1\xc9""Rh//shh/bin\x89\xe3\xcd\x80"
#
# __asm__(
#     "push   $0xb        \n\t"
#     "pop    %eax        \n\t"
#     "cltd               \n\t"
#     "xor    %ecx,%ecx   \n\t"
#     "push   %edx        \n\t"
#     "push   $0x68732f2f \n\t"
#     "push   $0x6e69622f \n\t"
#     "mov    %esp,%ebx   \n\t"
#     "int    $0x80       \n\t"
# );

shellcode = 'j\x0bX\x991\xc9Rh//shh/bin\x89\xe3\xcd\x80'
