#!/usr/bin/env python3

from pwn import *

{bindings}

context.binary = {bin_name}
context.terminal = ['tmux', 'neww']

def conn():
    if args.LOCAL:
        r = process({proc_args})
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

r = conn()

# good luck pwning :)

r.interactive()
