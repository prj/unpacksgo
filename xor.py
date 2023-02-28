import sys, binascii
def xors(string1, string2):
	slice = bytearray.fromhex(string1)
	key = bytearray.fromhex(string2)
	slicexor = bytearray()
	for nr,byte in enumerate(slice):
		slicexor += bytes({byte^key[nr % len(key)]})
	return slicexor

hexstring = binascii.hexlify(xors(sys.argv[1], sys.argv[2])).decode("utf-8")
i = 0
while i < len(hexstring):
	sys.stdout.write((hexstring[i] + hexstring[i+1] + " ").upper())
	i+=2