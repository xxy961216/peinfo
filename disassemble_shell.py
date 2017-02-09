from sys import argv
from capstone import *

def disasm_shellcode(argv):
  #args should be x86 32 or x86 64, ex: disassembly.py shellcode x86 32 "x41x42x43"
  CODE = argv[4].replace('\\x', '').decode('hex')
  print 'len =', len(CODE)

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


def diasm_file(argv):
  #this function reports shellcode binary saved as file, ex: save shellcode to file by insert shellcode bytes in HxD
  # usage: disassembly.py file Trojan.exe BytesToRead OffsetFromWhereToReadInDecimal # (200h = 512)
  import pydasm
  import binascii

  file = argv[2]
  bytez = int(argv[3])
  seek = int(argv[4])

  # Open, and read bytes out of the file,
  with open(file,'rb') as f:
      if seek:
        f.seek(seek)
      buffer = f.read(bytez)

  # Iterate through the buffer and disassemble 
  offset = 0
  while offset < len(buffer):
     i = pydasm.get_instruction(buffer[offset:], pydasm.MODE_32)
     print pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0)
     if not i:
       break
     offset += i.length

def main():
  if argv[1] == "file":
    diasm_file(argv)
  elif argv[1] == "shellcode":
    disasm_shellcode(argv)


if __name__ == '__main__':
  main()

