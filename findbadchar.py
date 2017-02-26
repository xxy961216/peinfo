# -*- coding: utf-8 -*-
import binascii,re

allchars = 	(
			"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
			"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
			"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
			"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
			"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
			"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
			"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
			"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
			"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
			"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
			"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
			"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
			"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
			"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
			"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
			"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
			)


def findBadChars(buffer=None):
	buffer =  buffer.replace(" ","").replace("\n","")
	buffer = binascii.unhexlify(buffer)

	badchars = ""
	for a in range(len(allchars)):
		try:
			goodchar = allchars[a]
			testchar = buffer[a]
			if goodchar != testchar:
				if len(hex(ord(goodchar))) == 3:
					badchars += "\\x0"+hex(ord(goodchar))[2]
				else:
					badchars += "\\"+hex(ord(goodchar))
		except IndexError:
			pass
	if len(badchars) == 0:
		return "None found"
	return badchars


a = '''01 02 03 B0 B0 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20
21 22 23 24 25 26 27 28 29 2A 2B 2C 2D B0 B0 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E B0 B0
41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F 60
61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F 80
81 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F 90 91 92 93 B0 B0 96 97 98 99 9A 9B 9C 9D 9E 9F A0
A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF B0
B0 C2 C3 C4 C5 C6 C7 C8 C9 CA CB CC CD CE CF D0 D1 D2 D3 D4 D5 D6 D7 D8 D9 DA DB DC DD DE DF E0
E1 E2 E3 E4 E5 E6 E7 E8 E9 EA EB EC ED EE EF F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FE FF 0D
0A 00 20 02 20 02 10 02 10 52 75 6E 6E 69 6E 67 00 02 10 02 00 02 00 02 02 03 10 02 28 AE C1 00
02 03 01 03 48 02 10 02 10 02 10 02 10 02 10 02 10 02 10 02 10 02 10 02 12 03 10 02 89 00 00 00
10 02 10 02 10 02 10 02 14 02 14 02 10 02 12 03 65 02 04 63 10 02 14 02 12 03 10 02 10 02 10 02
02 00 04 06 01 03 01 03 65 02 04 63 01 03 01 03 01 03 01 03 26 FE FF FF C0 00 C1 00 7F 00 00 00
00 00 C1 00 DA 01 00 00 01 03 00 00 00 00 00 00 01 03 10 02 4F 56 52 46 4C 57 20 41 41 41 41 41
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
41 41 41 41

'''

print findBadChars(a)
#\x04\x05\0x2e\0x2f\0x3f\0x40\0x94\0x95\0xc0\0xc1