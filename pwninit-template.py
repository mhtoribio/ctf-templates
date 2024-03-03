#!/usr/bin/env python3

from pwn import *

{bindings}

context.binary = {bin_name}
context.terminal = ['tmux', 'neww']

def conn():
    if args.REMOTE:
        io = remote("addr", 1337)
    else:
        io = process({proc_args})
    return io

gdbscript = """
c
"""
io = conn()
if args.GDB:
    gdb.attach(io, gdbscript=gdbscript)

def dbg(name, var):
    info(f"{name} = {hex(var)}")

# good luck pwning :)


io.interactive()
