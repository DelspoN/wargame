from subprocess import *
import os, socket

payload = []
payload.append('./input')
for i in range(ord('A')-1):
	payload.append(str(i))
payload.append('')			# input \x00
payload.append('\x20\x0a\x0d')
payload.append('8888')			# port number for stage5
for i in range(100-len(payload)):
	payload.append('dummy')
# for stage1

stdin_r, stdin_w = os.pipe()
stdout_r, stdout_w = os.pipe()
stderr_r, stderr_w = os.pipe()
os.write(stdin_w, "\x00\x0a\x00\xff")
os.write(stderr_w, "\x00\x0a\x02\xff")
# for stage2

os.environ["\xde\xad\xbe\xef"] = "\xca\xfe\xba\xbe"
print os.environ["\xde\xad\xbe\xef"]
# for stage3

f = open("\x0a", "w")
f.write("\x00\x00\x00\x00")
f.close()
# for stage4

process = Popen(payload, stdout=1, stderr=stderr_r, stdin=stdin_r)
os.close(stdin_r)
os.close(stdin_w)
os.close(stderr_r)
os.close(stderr_w)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 8888))
s.sendall("\xde\xad\xbe\xef")
s.close()
#for stage5

process.communicate()

# 1,2,3,4,5 clear
