#!/usr/bin/env python3

from pwn import *

{bindings}

context.binary = {bin_name}
context.terminal = ['tmux', 'neww']

def conn():
    if args.LOCAL:
        r = process({proc_args})
    else:
        r = remote("addr", 1337)

    return r

gdbscript = """
"""
r = conn()
if args.LOCAL:
    gdb.attach(r, gdbscript=gdbscript)

# good luck pwning :)


r.interactive()
