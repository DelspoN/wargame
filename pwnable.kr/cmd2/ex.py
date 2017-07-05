import sys

s = sys.argv[1]
result = ""
for i in range(len(s)):
	result = result + "\\%03o" % ord(s[i])
print result
