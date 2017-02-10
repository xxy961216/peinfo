from sys import argv
from capstone import *
import re,binascii


'''
	Args should be x86 32 or x86 64, ex: disassembly.py shellcode x86 32 "x41x42x43"
'''
def disasm_shellcode(argv):
	CODE = argv[4].replace(' ','').replace('\\x', '').decode('hex')
	print '\t\t------>Disassembly<------\n'

	ARCH = {
		'all'   : CS_ARCH_ALL,
		'arm'   : CS_ARCH_ARM,
		'arm64'   : CS_ARCH_ARM64,
		'mips'    : CS_ARCH_MIPS,
		'ppc'   : CS_ARCH_PPC,
		'x86'   : CS_ARCH_X86,
		'xcore'   : CS_ARCH_XCORE
	}

	MODE = {
		'16'    : CS_MODE_16, 
		'32'    : CS_MODE_32,
		'64'    : CS_MODE_64,
		'arm'   : CS_MODE_ARM,
		'be'    : CS_MODE_BIG_ENDIAN,
		'le'    : CS_MODE_LITTLE_ENDIAN,
		'micro'   : CS_MODE_MICRO,
		'thumb'   : CS_MODE_THUMB
	}

	md = Cs(ARCH[argv[2]], MODE[argv[3]])
	for i in md.disasm(CODE, 1):
		print '0x%x:\t%s\t%s' % (i.address, i.mnemonic, i.op_str)

'''
	Usage: disassembly.py file Trojan.exe BytesToRead OffsetFromWhereToReadInDecimal
'''
def diasm_file(argv):
	file = argv[2]
	bytez = int(argv[3])
	seek = int(argv[4])

	# Open, and read bytes out of the file,
	with open(file,'rb') as f:
			if seek:
				f.seek(seek)
			buffer = f.read(bytez)

	# Iterate through the buffer and disassemble 
	buffer = binascii.hexlify(buffer)
	hexDump(buffer,argv)
	disasm_shellcode(['','','x86','32',buffer])


def hexDump(data,argv):
	print;print "\t\t------->Hex Dump<-------";print
	data = re.findall('..?', data[:304])	# 304 max just for reference
	# bad_chars = ["0a", "0d", "09", "0b"]
	byte_line = ""
	# char_line = ""
	total_count = 0
	line_count = 1
	print "Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
	# print bytes, 16 at a time in both hex and ascii values
	for byte in data:
		if total_count <= len(data):
			if total_count >= 0:
				if line_count <= 16:
					byte_line += " "+byte
					# if byte in bad_chars:
					# 	char_line += "."
					# else:
					# 	byte = binascii.unhexlify(byte)
					# 	char_line += " "+byte
					line_count += 1
				else:
					offset = hex(int(argv[4]) + total_count - 16)
					printspace = 9 - len(offset)
					print offset + " "*printspace + byte_line 
					line_count = 1
					byte_line = ""
					# char_line = ""
					total_count -= 1 # to fix incorrect offset issue
		total_count += 1
	
	# print any remaining bytes 
	if byte_line != "":
		spacers = 48 - len(byte_line)
		print hex(int(offset, 16) + 16) + " "*printspace + byte_line + (" " * (spacers))
	print

def main():
	if argv[1] == "file":
		diasm_file(argv)
	elif argv[1] == "shellcode":
		disasm_shellcode(argv)


if __name__ == '__main__':
	main()
