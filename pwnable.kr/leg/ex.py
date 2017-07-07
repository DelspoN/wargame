from pwn import *

r = remote('pwnable.kr', 9007)
r.recvuntil("\x0a")

r.interactive()
