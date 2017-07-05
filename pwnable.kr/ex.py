s = ""
s += "./input"
s += " a"*(ord('A')-1)
s += " \x00"
s += " \x20\x0a\x0d"

print "./input" + " a"*(ord('A')-1) + " \x00" + " \x20\x0a\x0d"
