from pwn import *
import time

r = remote('pwnable.kr', 9007)
print r.recv('Ready')
