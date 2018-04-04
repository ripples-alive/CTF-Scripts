#!/usr/bin/env python
# coding:utf-8

from ctf import *

binary = '/bin/cat'
context.terminal = ['tmux', 'splitw', '-h']
mode = args['MODE'].lower()

code = context.binary = ELF(binary)
if args['LIBDEBUG']:
    os.environ['LD_LIBRARY_PATH'] = '/dbg/lib{}'.format(code.bits)
if args['LIBC']:
    os.environ['LD_PRELOAD'] = os.path.abspath(args['LIBC'])
libc = code.libc


def exploit():
    if mode == 'remote':
        io = remote('0', 4000)
        context.noptrace = True
    elif mode == 'debug':
        io = gdb.debug(binary)
        io.clean()
        io.gdb.c()
    else:
        io = process(binary)

    io.gdb.attach(gdbscript='''
        c
    ''')

    io.sendline('abc')
    assert io.recvline(keepends=False) == 'abc'

    assert not io.gdb.is_paused()
    io.gdb.interrupt()
    assert not io.gdb.is_running()

    io.sendline('xxx')
    out = io.recvline(keepends=False, timeout=2)
    if not out:
        info('recv timeout')
        io.gdb.detach()
        out = io.recvline(keepends=False)
    assert out == 'xxx'

    io.gdb.attach()
    if mode != 'debug':
        assert not io.gdb.is_running()
    io.sendline('gg')
    io.gdb.c()
    assert io.recvline(keepends=False) == 'gg'

    if not context.noptrace:
        io.gdb.execute('heapbase')
        heap_base = re.search(r'heapbase: (.*)',
                              io.gdb.get_last_line(4)).group(1)
        heap_base = int(heap_base, 16)
        info('heap base addr: %#x', heap_base)

    assert not io.gdb.is_paused()
    io.gdb.interrupt()
    io.gdb.send('reg')
    io.gdb.sendline(' rax')
    if not context.noptrace:
        out = re.search(r'RAX\s+(.*)', io.gdb.get_last_line(2)).group(1)
        rax = int(out, 0)
        info('rax: %#x', rax)

    if not context.noptrace:
        info('base addr: %#x', io.gdb.get_base())
        info('base addr: %#x', io.gdb.get_base('heap'))
        io.gdb.c()
        info('base addr: %#x', io.gdb.get_base('libc'))
        info('base addr: %#x', io.gdb.get_base('ld'))

    io.interactive()


if __name__ == '__main__':
    exploit()
