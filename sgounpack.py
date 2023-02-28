from __future__ import print_function
import sys, struct, os, configparser, time, ast, binascii
import tkinter as tk
from tkinter import filedialog
from collections import OrderedDict

def getWord32(img, pos):
	return struct.unpack("<I", img[pos:pos+4])[0]

def getWord24(img, pos):
	return struct.unpack(">I", b"\x00" + img[pos:pos+3])[0]

def decodeXOR(slice, key):
	slicexor = bytearray(len(slice))
	
	for nr in range(len(slice)):
		slicexor[nr] = slice[nr]^key[nr % len(key)]
	
	return slicexor
	
def decodeXORaddr(slice, base):
	slicexor = bytearray()
	for nr,byte in enumerate(slice):
		slicexor += bytes({byte^((nr + base) & 0xFF)})
	return slicexor
	
def stripBCBHead(imgxor):
	return imgxor[imgxor.index(b"\x1A\x01") + 2:]

def decodeBCB(imgxor, key, slen):
	imgxor = stripBCBHead(imgxor)
	slicexor = b""

	if (len(key) > 0):
		slicexor = decodeXOR(imgxor, key)
	else:
		slicexor = imgxor

	p = 0
	res = bytearray()
	while p < len(slicexor):
		l = struct.unpack(">H", slicexor[p:p+2])[0]
		p += 2

		fl = l >> 14
		l &= 0x3FFF

		if fl == 0: # literal
			res += slicexor[p:p+l]
			p += l
		elif fl == 1: # RLE
			res += bytearray([slicexor[p]] * l)
			p += 1
		elif fl == 3:
			if len(res) != slen:
				raise RuntimeError("Incorrect length!")
			if not (csum(res, getWord24(slicexor, p))):
				raise RuntimeError("Checksum mismatch!")
			break
		else:
			raise RuntimeError("ERROR! Unable to decode position: %X, value: %d, ID: %d" % (p, l, fl))
	return res

def csum(res, checksum):
	sum = 0
	i = 0
	while i < len(res):
		sum = (sum + res[i]) & 0xffffff
		i+=1
	if sum != checksum:
		print("ERROR! Checksum mismatch. Expected: 0x%X, got: 0x%X" % (checksum, sum))
		return False
	return True
	
def padtosize(filetopad, sizetopad):
	filetopad.seek(0, 2)
	if (filetopad.tell() < sizetopad):
		filetopad.write(bytearray([255] * (sizetopad - filetopad.tell())))
		
def deleterepeat(s):
	s = binascii.hexlify(s)
	i = (s+s).find(s, 1, -1)
	return binascii.unhexlify(s) if i == -1 else binascii.unhexlify(s[:i])
	
def nextEDC16Key(r3, r4):
	while True:
		r11 = r3 >> 31
		r10 = (r3 >> 30) & 0x01 # Binary bit 1
		r11 = r11 ^ r10
		r12 = (r3 >> 10) & 0x01 #Binary bit 21
		r11 = r11 ^ r12
		r10 = (r3 >> 0) & 0x01 # Binary bit 0
		r11 = r11 ^ r10
		r11 = r11 & 0xFF
		r6 = r3 >> 1
		if (r11 == 0):
			# clrrwi r5, r3, 1
			r5 = r3 & 0xFFFFFFFE
		else:
			# ori r5, r1, 1
			r5 = r3 | 1
		if (r3 != 0):
			r3 = 0
		else:
			r3 = 1

		r12 = (r5 >> 0) & 0x01
		r3 = r3 | r12
		r11 = r3 & 0xFF
		
		if (r11 == 0):
			r6 = r6 & 0x7FFFFFFF
		else:
			r6 = r6 | 0x80000000

		r4 = r4 + 0xFF
		r11 = r4 & 0xFF
		r3 = r6
		
		if (r11 != 0):
			continue
		return r3
		break
		
def decodeEDC16(slice):
	key = 0x3FE45D9A
	decoded = bytearray(len(slice))
	i = 0
	while i < len(slice):
		key = nextEDC16Key(key, 3)
		decoded[i] = (key & 0xFF) ^ slice[i]
		decoded[i+1] = ((key >> 8) & 0xFF) ^ slice[i+1]
		decoded[i+2] = ((key >> 16) & 0xFF) ^ slice[i+2]		
		decoded[i+3] = ((key >> 24) & 0xFF) ^ slice[i+3]
		i += 4
	return decoded

def freqtable(data, klen):
	freqtable = {}
	for x in range (0, klen):
		curfreq = {}
		for y in range (0, 256):
			curfreq[y] = 0
		freqtable[x] = curfreq

	for nr in range(len(data)):
		freqtable[nr % klen][data[nr]] += 1
		
	return freqtable

def findXORkeyfreq(bcbdata, byte, confidence, maxlen):
	data = stripBCBHead(bcbdata)
	keyFound = False
	key = bytearray()
	debug = config.getint("main", "debug", fallback=0)

	for curlen in reversed(range(4, maxlen+1)):
		fqtable = freqtable(data, curlen)
		key = bytearray(curlen)
		
		avgconf1 = 0
		for fqpos in sorted(fqtable):
			sortedlist = sorted(fqtable[fqpos].items(), key=lambda x: x[1], reverse=True)
			avgconf1 += 100 - sortedlist[1][1]/sortedlist[0][1]*100
			key[fqpos] = sortedlist[0][0] ^ byte
		
		avgconf1 = avgconf1/curlen
		
		if (avgconf1 >= confidence):
			key = deleterepeat(key)
			return key
	return b""

root = tk.Tk()
root.withdraw()

opts = {}
opts['filetypes'] = [('MAP files','.map')]
opts['title'] = "Select MAP file..."
opts['initialdir'] = sys.path[0]
filename = filedialog.askopenfilename(**opts)
config = configparser.ConfigParser()
config.read(filename)

opts = {}
opts['filetypes'] = [('SGO files','.sgo')]
opts['title'] = "Select SGO file..."
filename = filedialog.askopenfilename(**opts)
inputfile = open(filename, 'rb')
img = inputfile.read()
inputfile.close()

sgolen= getWord32(img, 0x2D)
print("File loaded: %d byte(s)" % len(img))
print()

cursection = 0
sections = {}

metastart = getWord32(img, 0x29)
metalen = getWord32(img, metastart)
blockstart = metastart+metalen+4

bcbkey = b""

while blockstart < sgolen:
	cursection +=1
	sectiondata = {}
	sectiondata["sectionaddr"] = getWord24(img, blockstart)
	sectiondata["sectioncrypt"] = img[blockstart+0x3]
	sectiondata["sectionlen"] = getWord24(img, blockstart+0x4)
	sectiondata["sectionerasestart"] = getWord24(img, blockstart+0x7)
	sectiondata["sectioneraseend"] = getWord24(img, blockstart+0xA)
	sectiondata["sectionprogstart"] = getWord24(img, blockstart+0xD)
	sectiondata["sectionprogend"] = getWord24(img, blockstart+0x10)
	sectiondata["sectionsgolen"] = getWord32(img, blockstart+0x15)
	sectiondata["sectionsgostart"] = blockstart
	
	blobstart = blockstart+0x19
	blobend = (blockstart+0x19+sectiondata["sectionsgolen"])
	sectiondata["blob"] = img[blobstart:blobend]
	blockstart = blobend
	
	sections[cursection] = sectiondata
	
	if (int(config.getint("section%d" % cursection, "ignore", fallback=0)) != 1):
		#Blank files
		suffix = config.get("section%d" % cursection, "suffix", fallback="")
		outputfile = open(filename[0:filename.rindex(".")] + suffix + ".sgo.bin", 'wb')
		outputfile.close()
		
for section in sections:
	crypto = int(config.getint("section%d" % section, "crypt", fallback=config.get("main", "crypt", fallback=0)))
	bcbkey = ast.literal_eval("\"" + config.get("section%d" % section, "key", fallback=config.get("main", "key", fallback="")) + "\"").encode("ISO-8859-1")
	
	if (int(config.getint("section%d" % section, "ignore", fallback=0)) != 1):
		outputdata = decodeXOR(sections[section]["blob"], b"\xFF")
		if (crypto == 1):
			# XOR and BCB with on the fly key cracking
			if (len(bcbkey) == 0):
				sectionsbysize = OrderedDict(sorted(sections.items(), key=lambda x: x[1]["sectionsgolen"]))
				for csection in sectionsbysize:
					if (int(config.getint("section%d" % csection, "ignore", fallback=0)) != 1):
						print("Finding key using section %d... " % csection, end="", flush=True)
						bcbkey = findXORkeyfreq(decodeXOR(sections[csection]["blob"], b"\xFF"), config.get("main", "xorbyte", fallback=0), config.get("main", "xorconfidence", fallback=50), config.get("main", "xormaxlen", fallback=32))
						if (len(bcbkey) > 0):
							try:
								outputdata = decodeBCB(outputdata, bcbkey, sections[section]["sectionlen"])
								print(" SUCCESS! key: %s (ASCII: %s)" % (binascii.hexlify(bcbkey).decode("ISO-8859-1").upper(), bcbkey.decode("ISO-8859-1")))
								print()
								break
							except RuntimeError:
								bcbkey = b""
						print(" FAILED!")
			else:
				print("Using key from map file: %s (ASCII: %s)" % (binascii.hexlify(bcbkey).decode("ISO-8859-1").upper(), bcbkey.decode("ISO-8859-1")))
				outputdata = decodeBCB(outputdata, bcbkey, sections[section]["sectionlen"])
		elif crypto == 2:
			# XOR only
			outputdata = decodeXOR(outputdata, key)
		elif crypto == 3:
			# BCB only
			outputdata = decodeBCB(outputdata, b"", sections[section]["sectionlen"])
		elif crypto == 4:
			# XOR Simos 8.3 style
			outputdata = decodeXORaddr(outputdata, sections[section]["sectionaddr"])
		elif crypto == 5:
			# EDC16 rolling key
			outputdata = decodeEDC16(outputdata)
		
	print("Section: %d" % section)
	print("Address: 0x%X" % sections[section]["sectionaddr"])
	print("Length : 0x%X" % sections[section]["sectionlen"])
	print("Erase  : 0x%X - 0x%X" % (sections[section]["sectionerasestart"], sections[section]["sectioneraseend"]))
	print("Prog   : 0x%X - 0x%X" % (sections[section]["sectionprogstart"], sections[section]["sectionprogend"]))
	print("Crypt  : %X" % sections[section]["sectioncrypt"])
	if (int(config.getint("main", "debug", fallback=0)) == 1):
		print("SGO adr: 0x%X" % sections[section]["sectionsgostart"])
		print("SGO len: 0x%X" % sections[section]["sectionsgolen"])
	
	#Write file
	if (int(config.getint("section%d" % section, "ignore", fallback=0)) != 1):
		suffix = config.get("section%d" % section, "suffix", fallback="")
		start = int(config.get("section%d" % section, "start", fallback=hex(sections[section]["sectionaddr"])), 16)
		filesize = int(config.get("section%d" % section, "filesize", fallback=config.get("main", "filesize", fallback="0x0")), 16)

		outputfilename = filename[0:filename.rindex(".")] + suffix + ".sgo.bin"
		print("Output : %s @ 0x%X" % (os.path.basename(outputfilename),  start))
		
		outputfile = open(outputfilename, 'rb+')
		padtosize(outputfile, start)

		outputfile.seek(start)
		outputfile.write(outputdata)

		padtosize(outputfile, filesize)
		outputfile.close()
	else: 
		print("Output : NONE")
		
	print()		

print("All done...")

if (int(config.getint("main", "debug", fallback=1)) == 1):
	input('Press ENTER to continue...')