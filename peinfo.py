import struct,json
from collections import OrderedDict
from datetime import datetime 
from sys import argv
from capstone import *
import re,binascii


MachineTypes = {'0x0': 'AnyMachineType','0x1d3': 'Matsushita AM33','0x8664': 'AMD64 (x64)','0x1c0': 'ARM LE',
				'0x1c4': 'ARMv7','0xaa64': 'ARMv8 x64','0xebc': 'EFIByteCode','0x14c': 'Intel x86',
				'0x200': 'Intel Itanium','0x9041': 'M32R','0x266': 'MIPS16','0x366': 'MIPS w/FPU',
				'0x466': 'MIPS16 w/FPU','0x1f0': 'PowerPC LE','0x1f1': 'PowerPC w/FP','0x166': 'MIPS LE',
				'0x1a2': 'Hitachi SH3','0x1a3': 'Hitachi SH3 DSP','0x1a6': 'Hitachi SH4','0x1a8': 'Hitachi SH5',
				'0x1c2': 'ARM or Thumb -interworking','0x169': 'MIPS little-endian WCE v2'
				}

ArchTypes = {"0x10b":"32","0x20b":"64"}
ImageHeaderSignatures = {"0x10b":"PE32","0x20b":"PE64"}

pInfo = OrderedDict()

class peinfo():
	def __init__(self,FILE=None,ARCH=None,MACHINE=None,SECTIONS=None,PE_SIG=None,OFFSET=None):
		if isinstance(FILE, file):
			self.binary = FILE
		else:
			if FILE:
				self.binary = file(FILE,"rb")
		self.FILE = FILE
		self.ARCH = ARCH
		self.MACHINE = MACHINE
		self.SECTIONS = SECTIONS
		self.PE_SIG = PE_SIG
		self.OFFSET = OFFSET


	def __repr__(self):
		self.overview()
		return self.json()


	def parseCharacteristics(self,xbyte,typez=None):
		nlist = OrderedDict()
		xbyte = int(xbyte,16)
		peKeyValue = OrderedDict({0x001:"IMAGE_FILE_RELOCS_STRIPPED",0x002:"IMAGE_FILE_EXECUTABLE_IMAGE",0x004:"IMAGE_FILE_LINE_NUMS_STRIPPED",
					0x008:"IMAGE_FILE_LOCAL_SYMS_STRIPPED",0x010:"IMAGE_FILE_AGGRESIVE_WS_TRIM",0x020:"IMAGE_FILE_LARGE_ADDRESS_AWARE",
					0x080:"IMAGE_FILE_BYTES_REVERSED_LO",0x0100:"IMAGE_FILE_32BIT_MACHINE",0x0200:"IMAGE_FILE_DEBUG_STRIPPED",
					0x0400:"IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP",0x0800:"IMAGE_FILE_NET_RUN_FROM_SWAP",0x1000:"IMAGE_FILE_SYSTEM",
					0x2000:"IMAGE_FILE_DLL",0x4000:"IMAGE_FILE_UP_SYSTEM_ONLY",0x8000:"IMAGE_FILE_BYTES_REVERSED_HI"})
		subsystemKeyValue = OrderedDict({0x0000:"IMAGE_SUBSYSTEM_UNKNOWN",0x0001:"IMAGE_SUBSYSTEM_NATIVE",0x0002:"IMAGE_SUBSYSTEM_WINDOWS_GUI",
					0x0003:"IMAGE_SUBSYSTEM_WINDOWS_CUI",0x0005:"IMAGE_SUBSYSTEM_OS2_CUI",0x0007:"IMAGE_SUBSYSTEM_POSIX_CUI",
					0x0009:"IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",0x0010:"IMAGE_SUBSYSTEM_EFI_APPLICATION",0x0011:"IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
					0x0012:"IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",0x0013:"IMAGE_SUBSYSTEM_EFI_ROM",0x0014:"IMAGE_SUBSYSTEM_XBOX",
					0x0016:"IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"})
		dllKeyValue = OrderedDict({0x0001:'Reserved',0x0002:'Reserved',0x0004:'Reserved',0x0008:'Reserved',
					0x0040:'IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE',0x0080:'IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY',
					0x0100:'IMAGE_DLLCHARACTERISTICS_NX_COMPAT',0x0200:'IMAGE_DLLCHARACTERISTICS_NO_ISOLATION',
					0x0400:'IMAGE_DLLCHARACTERISTICS_NO_SEH',0x0800:'IMAGE_DLLCHARACTERISTICS_NO_BIND',
					0x1000:'Reserved',0x2000:'IMAGE_DLLCHARACTERISTICS_WDM_DRIVER',0x4000:'Reserved',
					0x8000:'IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE'})
		sectionKeyValue = OrderedDict({0x00000000:'IMAGE_SCN_TYPE_REG',0x00000001:'IMAGE_SCN_TYPE_DSECT',0x00000002:'IMAGE_SCN_TYPE_NOLOAD',
					0x00000004:'IMAGE_SCN_TYPE_GROUP',0x00000008:'IMAGE_SCN_TYPE_NO_PAD',0x00000010:'IMAGE_SCN_TYPE_COPY',
					0x00000020:'IMAGE_SCN_CNT_CODE',0x00000040:'IMAGE_SCN_CNT_INITIALIZED_DATA',0x00000080:'IMAGE_SCN_CNT_UNINITIALIZED_DATA',
					0x00000100:'IMAGE_SCN_LNK_OTHER',0x00000200:'IMAGE_SCN_LNK_INFO',0x00000400:'IMAGE_SCN_TYPE_OVER',
					0x00000800:'IMAGE_SCN_LNK_REMOVE',0x00001000:'IMAGE_SCN_LNK_COMDAT',0x00008000:'IMAGE_SCN_MEM_FARDATA',
					0x00020000:'IMAGE_SCN_MEM_PURGEABLE',0x00040000:'IMAGE_SCN_MEM_LOCKED',0x00080000:'IMAGE_SCN_MEM_PRELOAD',
					0x00100000:'IMAGE_SCN_ALIGN_1BYTES',0x00200000:'IMAGE_SCN_ALIGN_2BYTES',0x00300000:'IMAGE_SCN_ALIGN_4BYTES',
					0x00400000:'IMAGE_SCN_ALIGN_8BYTES',0x00500000:'IMAGE_SCN_ALIGN_16BYTES',0x00600000:'IMAGE_SCN_ALIGN_32BYTES',
					0x00700000:'IMAGE_SCN_ALIGN_64BYTES',0x00800000:'IMAGE_SCN_ALIGN_128BYTES',0x00900000:'IMAGE_SCN_ALIGN_256BYTES',
					0x00A00000:'IMAGE_SCN_ALIGN_512BYTES',0x00B00000:'IMAGE_SCN_ALIGN_1024BYTES',0x00C00000:'IMAGE_SCN_ALIGN_2048BYTES',
					0x00D00000:'IMAGE_SCN_ALIGN_4096BYTES',0x00E00000:'IMAGE_SCN_ALIGN_8192BYTES',0x01000000:'IMAGE_SCN_LNK_NRELOC_OVFL',
					0x02000000:'IMAGE_SCN_MEM_DISCARDABLE',0x04000000:'IMAGE_SCN_MEM_NOT_CACHED',0x08000000:'IMAGE_SCN_MEM_NOT_PAGED',
					0x10000000:'IMAGE_SCN_MEM_SHARED',0x20000000:'IMAGE_SCN_MEM_EXECUTE',0x40000000:'IMAGE_SCN_MEM_READ',
					0x80000000:'IMAGE_SCN_MEM_WRITE'})
		metaflagsKeyValue = OrderedDict({0x00000001:"ILOnly",0x00000002:"Requires32Bit",0x00000004:"ILLibrary",0x00000008:"StrongNameSigned",
					0x00000010:"NativeEntryPoint",0x00010000:"TrackDebugData",0x00020000:"Prefers32Bit"})
		listOfDicts = [peKeyValue,subsystemKeyValue,dllKeyValue,sectionKeyValue,metaflagsKeyValue]
		keyValue = listOfDicts[typez]
		for value, msg in keyValue.iteritems():
			if typez == 1:
				nlist['Flag'] = xbyte
				if (xbyte == value):
					nlist['Meaning'] = msg
			else:
				if (xbyte & value):
					nlist[hex(value)] = msg
		return nlist


	def json(self,isdict=0):
		if isdict:
			return pInfo
		return json.dumps(pInfo,indent=4)


	# worst print implementation ever
	def printOut(self,d=pInfo,g=0):
		for k, v in d.iteritems():
			if isinstance(v, dict):
				if g == 0:
					print '\n\n'+'='*20+k+"="*20
				else:
					print '\t'*g+k.upper()
				self.printOut(v,g+1)
			else:
				if isinstance(v,list):
					for u in v:
						print '\t'*g+k
						self.printOut(u,g+1)
				else:
					diff = 10-len(k)
					print '\t'*g+k.upper()+' '*diff+':'+' '*5+str(v)


	def convert_hex_to_ascii(self,h):
		chars = []
		while h != 0x0:
			chars.append(chr(h & 0xFF))
			h = h >> 8
		return ''.join(chars)


	def fileOffset(self,rva,section=None):
		if section:
			tva = int(pInfo["SECTIONS"][section]["VirtualAddress"]["value"],16)
			tra = int(pInfo["SECTIONS"][section]["RawAddress"]["value"],16)
			sectionEnd = tra + pInfo["SECTIONS"][section]["RawSize"]["value"]
			offset = rva - tva + tra
			return offset
		else:
			va = 0; ra = 0;
			sections = pInfo["SECTIONS"]
			for section in sections:
				tva = int(pInfo["SECTIONS"][section]["VirtualAddress"]["value"],16)
				tra = int(pInfo["SECTIONS"][section]["RawAddress"]["value"],16)
				sectionEnd = tra + pInfo["SECTIONS"][section]["RawSize"]["value"]
				if rva >= tva and rva <= sectionEnd:
					va = tva; ra = tra
					break
			offset = rva - va + ra
			return [offset,section]


	#needs testing
	def exportList(self,search=None,ords=False):
		rva = int(pInfo["PE"]["ImageOptionalHeader"]["DirectoryStructures"]["ExportDirectoryRVA"]["value"],16)
		offSetInfo = self.fileOffset(rva)
		fileOffset = offSetInfo[0]
		section = offSetInfo[1]
		exports = OrderedDict()
		self.binary.seek(fileOffset)
		exports["Characteristics"] = self.structer('<I',True)
		exports["TimeDateStamp"] = {'offset':self.binary.tell(),'bytes':4,
				'value':datetime.fromtimestamp(int(struct.unpack("<I",self.binary.read(4))[0])).strftime('%Y-%m-%d %H:%M:%S')}
		exports["MajorVersion"]	= self.structer('<H',True)
		exports["MinorVersion"]	= self.structer('<H',True)
		exports["Name"]	= self.structer('<I',True)
		exports["Base"]	= self.structer('<I',True)
		exports["NumberOfFunctions"] = self.structer('<I',True)
		exports["NumberOfNames"] = self.structer('<I',True)
		exports["AddressOfFunctions"] = self.structer('<I',True)
		exports["AddressOfNames"] = self.structer('<I',True)
		exports["AddressOfNameOrdinals"] = self.structer('<I',True)
		nFuncs = int(exports["NumberOfFunctions"]["value"],16)
		nNames = int(exports["NumberOfNames"]["value"],16)
		exportsDict = OrderedDict()
		nameFileOffset = {}
		funcrva = []
		ordDict = {}
		#storing all function RVAs
		for x in range(0,nFuncs):
			e = self.structer('<I',True)["value"]
			funcrva.append(e)
		#storing all name RVAs
		for y in range(0,nNames):
			rva = self.structer('<I',False)["value"]
			fileOffset = self.fileOffset(rva,section)
			nameFileOffset.update({y:fileOffset})
		#storing all ordinals
		nOrds = nFuncs - (nFuncs - nNames)
		for z in range(0,nOrds):	
			ordinal = self.structer('<H',False)["value"]
			ordDict.update({ordinal:hex(nameFileOffset[z])})
		for u in range(len(funcrva)):
			try:
				tempname = ""
				self.binary.seek(int(ordDict[u],16))
				while True:
					byte = self.binary.read(1)
					if byte != "\x00":
						tempname += byte
					else:
						break
				if ords:
					exportsDict.update({tempname:[funcrva[u],hex(u)]})
				else:
					exportsDict.update({tempname:funcrva[u]})
			except KeyError:
				pass

		if search:
			try:
				if ords:
					addr = int(pInfo["PE"]["ImageOptionalHeader"]["ImageBase"]["value"],16) + int(exportsDict[search][0],16)
				else:
					addr = int(pInfo["PE"]["ImageOptionalHeader"]["ImageBase"]["value"],16) + int(exportsDict[search],16)
				return hex(addr)
			except KeyError:
				return None
		exports["ExportsList"] = exportsDict
		pInfo["ExportDirectory"] = exports


	def importList(self,search=None,ords=False):
		rva = int(pInfo["PE"]["ImageOptionalHeader"]["DirectoryStructures"]["ImportDirectoryRVA"]["value"],16)
		size = int(pInfo["PE"]["ImageOptionalHeader"]["DirectoryStructures"]["ImportDirectorySize"]["value"],16)
		offSetInfo = self.fileOffset(rva)
		fileOffset = offSetInfo[0]
		section = offSetInfo[1]
		end = fileOffset + size
		self.binary.seek(fileOffset)
		n = 0; importDescriptor = []; ssd = OrderedDict()
		while True:
			rr = ["OriginalFirstThunk","TimeDateStamp","ForwarderChain","NameRVA","FirstThunk"]
			z = self.structer('<I',True)["value"]
			ssd.update({rr[n]:z})
			n += 1
			if self.binary.tell() >= end:
				ssd.clear()
				break
			if n == 5:
				importDescriptor.append(ssd)
				ssd = OrderedDict()
				n = 0
		for imp0rt in importDescriptor:
			rva = int(imp0rt["NameRVA"],16)
			nameOffset = self.fileOffset(rva,section)
			tempname = ""; 
			self.binary.seek(nameOffset)
			while True:
				byte = self.binary.read(1)
				if byte != "\x00":
					tempname += byte
				else:
					break
			imp0rt = {tempname:imp0rt}
			oftarray = []; 
			oftRva = int(imp0rt[tempname]["OriginalFirstThunk"],16)
			oftFo = self.fileOffset(oftRva,section)
			self.binary.seek(oftFo)
			while True:
				if self.PE_SIG == "0x20b":
					x = self.structer('<Q',True)["value"]
				else:
					x = self.structer('<I',True)["value"]
				if x == "0x0":	#chk null terminator
					break
				else:
					if x[:4] != "0x80": #check if import by oridinal only or not
						cAddr = self.binary.tell()
						xFo = self.fileOffset(int(x,16),section)
						self.binary.seek(xFo)
						hint = hex(struct.unpack('<H', self.binary.read(2))[0])
						tempname = ""
						while True:
							byte = self.binary.read(1)
							if byte != "\x00":
								tempname += byte
							else:
								# print oftFo,tempname
								break
						self.binary.seek(cAddr)
					else:
						tempname = ""
						hint = x[-5:]
						# print hint
				oftarray.append((x,hint,tempname))
			print json.dumps(oftarray,indent=4)


	# temp experimental method, much slower than the other one but better,,,, BROKEN
	def findCaves(self,size=500):
		s = open(self.FILE,"rb")
		start = 0
		end = 0
		cave = ""
		caveList = []
		while True:
			if not start:
				start = s.tell()
			a = binascii.hexlify(s.read(1))
			if a == "00":
				cave += a
			else:
				bytez = len(cave)/2
				end = s.tell()-1
				if bytez >= size:
					caveList.append({"start":hex(start),"end":hex(end),"size":end-start})
				cave = ""; start = ""; end= ""
			if not a:
				break
		return caveList


	# function shamelessly taken from thebackdoor-factory with some modifications, will be changed later on
	# https://github.com/secretsquirrel/the-backdoor-factory/blob/master/pebin.py#L924
	def find_all_caves(self,size=250):
		SIZE_CAVE_TO_FIND = size
		BeginCave = 0
		Tracking = 0
		count = 1
		caveTracker = []
		caveSpecs = []
		self.binary.seek(0)
		# Slow way
		while True:
			try:
				s = struct.unpack("<b", self.binary.read(1))[0]
			except Exception as e:
				break
			if s == 0:
				if count == 1:
					BeginCave = Tracking
				count += 1
			else:
				if count >= SIZE_CAVE_TO_FIND:
					caveSpecs.append(BeginCave)
					caveSpecs.append(Tracking)
					caveTracker.append(caveSpecs)
					print caveSpecs
				count = 1
				caveSpecs = []

			Tracking += 1

		pInfo['CAVES'] = OrderedDict()
		pInfo['CAVES']['TOTAL'] = None
		pInfo['CAVES']['INSIDE_SECTION'] = OrderedDict()
		pInfo['CAVES']['OUTSIDE_SECTION'] = []
		for caves in caveTracker:
			for section in pInfo['SECTIONS']:
				sectionFound = False
				sectionSize = pInfo['SECTIONS'][section]['RawSize']['value']
				sectionStart = int(pInfo['SECTIONS'][section]['RawAddress']['value'],16)
				sectionEnd = sectionStart + sectionSize
				caveLength = caves[1] - caves[0]
				if caves[0] >= sectionStart and caves[1] <= sectionEnd and SIZE_CAVE_TO_FIND <= caveLength:
					data = OrderedDict()
					data['CaveStart'] = hex(caves[0])
					data['CaveEnd'] = hex(caves[1])
					data['CaveLength'] = caveLength
					try:
						if isinstance(pInfo['CAVES']['INSIDE_SECTION'][section],list):
							pass
					except KeyError:
						pInfo['CAVES']['INSIDE_SECTION'][section] = []
					pInfo['CAVES']['INSIDE_SECTION'][section].append(data)
					sectionFound = True
					break
			if sectionFound is False:
				try:
					data = OrderedDict()
					data['CaveStart'] = hex(caves[0])
					data['CaveEnd'] = hex(caves[1])
					data['CaveLength'] = caves[1] - caves[0]
					try:
						if isinstance(pInfo['CAVES']['OUTSIDE_SECTION'],list):
							pass
					except KeyError:
						pInfo['CAVES']['OUTSIDE_SECTION'] = []
					pInfo['CAVES']['OUTSIDE_SECTION'].append(data)
				except Exception as e:
					pass
		pInfo['CAVES']['TOTAL'] = len(caveTracker)
		self.binary.close()


	def structer(self,formatt,hexz,special=None,arg=None):
		u = {'<B':1,'<H':2,'<I':4,'<L':4,'<Q':8}
		self.OFFSET = hex(self.binary.tell())
		bytez = u[formatt]
		if hexz:
			# rstrip coz of windows hex() returns type ,e.g:L (long)
			value = hex(struct.unpack(formatt,self.binary.read(bytez))[0]).rstrip("L")
		else:
			value = struct.unpack(formatt,self.binary.read(bytez))[0]
		if isinstance(special, dict):
			value = special[value]
		elif isinstance(special, list):
			value = special[value]
		elif special:
			if arg:
				value = special(value,arg)
			else:
				value = special(value)
		return {'value':value,'offset':self.OFFSET,'bytes':bytez}


	def checkBinary(self):
		self.binary.seek(0)
		x = struct.unpack("<H",self.binary.read(2))[0]
		#check for valid MSDOS header sig
		if hex(x) == "0x5a4d":
			pInfo['MSDOS'] = OrderedDict()
			self.binary.seek(0)
			pInfo['MSDOS']['Signature'] = self.structer('<H',True)
			self.binary.seek(0+6)
			pInfo['MSDOS']['RelocationTables'] = self.structer('<H',False)
			pInfo['MSDOS']['MinAlloc'] = self.structer('<H',True)
			pInfo['MSDOS']['MaxAlloc'] = self.structer('<H',True)
			self.binary.seek(60)
			pInfo['MSDOS']['e_lfanew'] = self.structer('<L',True)
		# collecting DOS STUB info
		pInfo['MSDOS_STUB'] = OrderedDict()
		garbage_check = int(pInfo['MSDOS']['e_lfanew']['value'],16)-self.binary.tell()
		pInfo['MSDOS_STUB'] = {'bytes':self.binary.tell(),
								'offset':self.binary.tell(),'value':hex(struct.unpack("<I",self.binary.read(4))[0])}
		# checking whether any garbade data exists in between DOS_STUB and PE_HEADER
		if garbage_check > 64:
			pInfo['GARBAGE'] = OrderedDict()
			pInfo['GARBAGE'] = {'bytes':garbage_check-64,
									'value':hex(struct.unpack("<I",self.binary.read(4))[0]),
									'offset':pInfo['MSDOS_STUB']['offset']+64}
		# check for valid PE header sig
		self.binary.seek(int(pInfo['MSDOS']['e_lfanew']['value'],16))
		offset = self.binary.tell()
		x = struct.unpack("<L",self.binary.read(4))[0]
		if hex(x) == "0x4550":
			pInfo['PE'] = OrderedDict()
			pInfo['PE']['Signature'] = {'value':hex(x),'offset':offset,'bytes':4}
			pInfo['PE']['Machine'] = self.structer('<H',True,MachineTypes)
			pInfo['PE']['TotalSections'] = self.structer('<H',False)
			pInfo['PE']['TimeStamp'] = {'offset':self.binary.tell(),'bytes':4,
				'value':datetime.fromtimestamp(int(struct.unpack("<L",self.binary.read(4))[0])).strftime('%Y-%m-%d %H:%M:%S')}
			pInfo['PE']['PtrToSymbolTable'] = self.structer('<L',True)
			pInfo['PE']['NoOfSymbols'] = self.structer('<L',False)
			pInfo['PE']['SizeOfOptionalHeader'] = self.structer('<H',False)
			pInfo['PE']['Characteristics'] = OrderedDict()
			pInfo['PE']['Characteristics']['Signature'] = self.structer('<H',True)
			pInfo['PE']['Characteristics']['Flags'] = self.parseCharacteristics(pInfo['PE']['Characteristics']['Signature']['value'],0)
			pInfo['PE']['ImageOptionalHeader'] = OrderedDict()
			#setting PE_SIG for 64bit adjustments
			self.PE_SIG = self.structer('<H',True)['value']
			pInfo['PE']['ImageOptionalHeader']['Signature'] = {'offset':self.OFFSET,'value':self.PE_SIG,'bytes':2}
			# pInfo['PE']['ImageOptionalHeader']['SignatureMeaning'] = ImageHeaderSignatures[pInfo['PE']['ImageOptionalHeader']['Signature']['value']]
			pInfo['PE']['ImageOptionalHeader']['MajorLinkerVersion'] = self.structer('<B',True)
			pInfo['PE']['ImageOptionalHeader']['MinorLinkerVersion'] = self.structer('<B',True)
			pInfo['PE']['ImageOptionalHeader']['SizeOfCode'] = self.structer('<I',True)
			pInfo['PE']['ImageOptionalHeader']['SizeOfInitializedData'] = self.structer('<I',False)
			pInfo['PE']['ImageOptionalHeader']['SizeOfUninitializedData'] = self.structer('<I',False)
			pInfo['PE']['ImageOptionalHeader']['AddressOfEntryPoint'] = self.structer('<I',True)
			pInfo['PE']['ImageOptionalHeader']['BaseOfCode'] = self.structer('<I',True)
			#making 64bit adjustments
			if self.PE_SIG == "0x10b":
					pInfo['PE']['ImageOptionalHeader']['BaseOfData'] = self.structer('<I',True)
			if self.PE_SIG == "0x20b":
				formatz = "<Q"
			else:
				formatz = "<I"
			pInfo['PE']['ImageOptionalHeader']['ImageBase'] = self.structer(formatz,True)
			pInfo['PE']['ImageOptionalHeader']['SectionAlignment'] = self.structer('<I',True)
			pInfo['PE']['ImageOptionalHeader']['FileAlignment'] = self.structer('<I',True)
			pInfo['PE']['ImageOptionalHeader']['MajorOperatingSystemVersion'] = self.structer('<H',False)
			pInfo['PE']['ImageOptionalHeader']['MinorOperatingSystemVersion'] = self.structer('<H',False)
			pInfo['PE']['ImageOptionalHeader']['MajorImageVersion'] = self.structer('<H',False)
			pInfo['PE']['ImageOptionalHeader']['MinorImageVersion'] = self.structer('<H',False)
			pInfo['PE']['ImageOptionalHeader']['MajorSubsystemVersion'] = self.structer('<H',False)
			pInfo['PE']['ImageOptionalHeader']['MinorSubsystemVersion'] = {'offset':self.binary.tell(),'value':struct.unpack("<H",self.binary.read(2))[0]}
			pInfo['PE']['ImageOptionalHeader']['Win32VersionValue'] = self.structer('<I',False)
			pInfo['PE']['ImageOptionalHeader']['SizeOfImage'] = self.structer('<I',True)
			pInfo['PE']['ImageOptionalHeader']['SizeOfHeaders'] = self.structer('<I',True)
			pInfo['PE']['ImageOptionalHeader']['CheckSum'] = self.structer('<I',True)
			pInfo['PE']['ImageOptionalHeader']['Subsystem'] = self.structer('<H',True,self.parseCharacteristics,arg=1)
			dllsig = hex(struct.unpack("<H",self.binary.read(2))[0])
			pInfo['PE']['ImageOptionalHeader']['DllCharacteristics'] = OrderedDict({'Signature':	dllsig})
			pInfo['PE']['ImageOptionalHeader']['DllCharacteristics']['Flags'] = self.parseCharacteristics(dllsig,2)
			pInfo['PE']['ImageOptionalHeader']['SizeOfStackReserve'] = self.structer(formatz,True)
			pInfo['PE']['ImageOptionalHeader']['SizeOfStackCommit'] = self.structer(formatz,True)
			pInfo['PE']['ImageOptionalHeader']['SizeOfHeapReserve'] = self.structer(formatz,True)
			pInfo['PE']['ImageOptionalHeader']['SizeOfHeapCommit'] = self.structer(formatz,True)
			pInfo['PE']['ImageOptionalHeader']['LoaderFlags'] = self.structer('<I',True)
			pInfo['PE']['ImageOptionalHeader']['NumberOfRvaAndSizes'] = self.structer('<I',False)
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures'] = OrderedDict()
			peStructures = ["ExportDirectoryRVA","ExportDirectorySize","ImportDirectoryRVA","ImportDirectorySize","ResourceDirectoryRVA",
							"ResourceDirectorySize","ExceptionDirectoryRVA","ExceptionDirectorySize","SecurityDirectoryRVA",
							"SecurityDirectorySize","RelocationDirectoryRVA","RelocationDirectorySize","DebugDirectoryRVA","DebugDirectorySize",
							"ArchitechtureDirectoryRVA","ArchitechtureDirectorySize","GlobalPtr","Reserved","TLSDirectoryRVA","TLSDirectorySize",
							"ConfigurationDirectoryRVA","ConfigurationDirectorySize","BoundImportDirectoryRVA","BoundImportDirectorySize",
							"ImportAddressTableDirectoryRVA","ImportAddressTableDirectorySize","DelayImportDirectoryRVA","DelayImportDirectorySizes",
							"CLRRuntimeHeaderRVA","CLRRuntimeHeaderSize","Reserved1","Reserved2"]
			for structure in peStructures:
				offset = self.binary.tell()
				pInfo['PE']['ImageOptionalHeader']['DirectoryStructures'][structure] = self.structer('<I',True)

			pInfo['SECTIONS'] = OrderedDict()
			#starting section enumeration
			sections = int(pInfo['PE']['TotalSections']['value'])
			for i in range(0,sections):
				name = self.convert_hex_to_ascii(self.structer('<Q',False)['value'])
				data = OrderedDict()
				data['VirtualSize'] = self.structer('<I',False)
				data['VirtualAddress'] = self.structer('<I',True)
				data['RawSize'] = self.structer('<I',False)
				data['RawAddress'] = self.structer('<I',True)
				data['PointerToRelocations'] = self.structer('<I',True)
				data['PointerToLinenumbers'] = self.structer('<I',False)
				data['NumberOfRelocations'] = self.structer('<H',False)
				data['NumberOfLinenumbers'] = self.structer('<H',False)
				data['Characteristics'] = OrderedDict()
				t1 = self.structer('<I',True)
				data['Characteristics'] = t1
				data['Characteristics']['Flags'] = self.parseCharacteristics(t1['value'],3)
				pInfo['SECTIONS'][name] = data
			# updating filealignment with start and end offset along with length of alignment
			fa_start = self.binary.tell()
			fa_end = int(pInfo['PE']['ImageOptionalHeader']['FileAlignment']['value'],16)
			fa_length = fa_end-fa_start
			pInfo['PE']['ImageOptionalHeader']['FileAlignment']['Location'] = {'offset':fa_start,
				'value':None,'bytes':int(str(fa_length).lstrip('-'))}
			self.binary.seek(fa_end)
			padded_offset = int(pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['CLRRuntimeHeaderRVA']['value'] ,16) % int(pInfo['PE']['ImageOptionalHeader']['SectionAlignment']['value'],16) + self.binary.tell()
			if self.SECTIONS == 3:
				self.binary.seek(padded_offset)
				pInfo['IMPORT_TABLES'] = OrderedDict()
				pInfo['IMPORT_TABLES']['CLRHeaderSize'] = self.structer('<I',True)
				pInfo['IMPORT_TABLES']['MajorRuntimeVersion'] = self.structer('<H',True)
				pInfo['IMPORT_TABLES']['MinorRuntimeVersion'] = self.structer('<H',True)
				pInfo['IMPORT_TABLES']['MetadataRVA'] = self.structer('<I',True)
				pInfo['IMPORT_TABLES']['MetadataSize'] = self.structer('<I',False)
				pInfo['IMPORT_TABLES']['Flags'] = self.parseCharacteristics(self.structer('<I',True)['value'],4)
				pInfo['IMPORT_TABLES']['EntryPointToken'] = self.structer('<I',True)

		return 'Valid %s binary found' % (ImageHeaderSignatures[str(self.PE_SIG)])


	#lazy implementation for only main info, might be fixed later on.
	def overview(self):
		pInfo.clear()
		self.binary.seek(0)
		x = struct.unpack("<H",self.binary.read(2))[0]
		#check for valid MSDOS header sig
		if hex(x) == "0x5a4d":
			pInfo['MSDOS'] = OrderedDict()
			self.binary.seek(0)
			pInfo['MSDOS']['Signature'] = hex(struct.unpack("<H",self.binary.read(2))[0]).rstrip('L')
			self.binary.seek(0+6)
			pInfo['MSDOS']['RelocationTables'] = struct.unpack("<H",self.binary.read(2))[0]
			pInfo['MSDOS']['MinAlloc'] = hex(struct.unpack("<H",self.binary.read(2))[0]).rstrip('L')
			pInfo['MSDOS']['MaxAlloc'] = hex(struct.unpack("<H",self.binary.read(2))[0]).rstrip('L')
			self.binary.seek(60)
			pInfo['MSDOS']['e_lfanew'] = hex(struct.unpack("<L",self.binary.read(4))[0]).rstrip('L')

		# check for valid PE header sig
		self.binary.seek(int(pInfo['MSDOS']['e_lfanew'],16))
		x = struct.unpack("<L",self.binary.read(4))[0]
		if hex(x) == "0x4550":
			pInfo['PE'] = OrderedDict()
			pInfo['PE']['Signature'] = hex(x)
			pInfo['PE']['Machine'] = MachineTypes[hex(struct.unpack("<H",self.binary.read(2))[0]).rstrip('L')]
			pInfo['PE']['TotalSections'] = struct.unpack("<H",self.binary.read(2))[0]
			pInfo['PE']['TimeStamp'] = datetime.fromtimestamp(int(struct.unpack("<L",self.binary.read(4))[0])).strftime('%Y-%m-%d %H:%M:%S')
			pInfo['PE']['PtrToSymbolTable'] = hex(struct.unpack("<L",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['NoOfSymbols'] = struct.unpack("<L",self.binary.read(4))[0]
			pInfo['PE']['SizeOfOptionalHeader'] = struct.unpack("<H",self.binary.read(2))[0]
			pInfo['PE']['Characteristics'] = OrderedDict()
			pInfo['PE']['Characteristics']['Signature'] = hex(struct.unpack("<H",self.binary.read(2))[0]).rstrip('L')
			pInfo['PE']['Characteristics']['Flags'] = self.parseCharacteristics(pInfo['PE']['Characteristics']['Signature'],0)
			pInfo['PE']['ImageOptionalHeader'] = OrderedDict()
			self.PE_SIG = hex(struct.unpack("<H",self.binary.read(2))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['Signature'] = self.PE_SIG
			pInfo['PE']['ImageOptionalHeader']['SignatureMeaning'] = ImageHeaderSignatures[pInfo['PE']['ImageOptionalHeader']['Signature']]
			pInfo['PE']['ImageOptionalHeader']['MajorLinkerVersion'] = hex(struct.unpack("<B",self.binary.read(1))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['MinorLinkerVersion'] = hex(struct.unpack("<B",self.binary.read(1))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['SizeOfCode'] = struct.unpack("<I",self.binary.read(4))[0]
			pInfo['PE']['ImageOptionalHeader']['SizeOfInitializedData'] = struct.unpack("<I",self.binary.read(4))[0]
			pInfo['PE']['ImageOptionalHeader']['SizeOfUninitializedData'] = struct.unpack("<I",self.binary.read(4))[0]
			pInfo['PE']['ImageOptionalHeader']['AddressOfEntryPoint'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['BaseOfCode'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			#making 64bit adjustments
			if self.PE_SIG == "0x10b":
				pInfo['PE']['ImageOptionalHeader']['BaseOfData'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			if self.PE_SIG == "0x20b":
				bytez = 8; formatz = "<Q"
			else:
				bytez = 4; formatz = "<I"
			pInfo['PE']['ImageOptionalHeader']['ImageBase'] = hex(struct.unpack(formatz,self.binary.read(bytez))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['SectionAlignment'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['FileAlignment'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['MajorOperatingSystemVersion'] = struct.unpack("<H",self.binary.read(2))[0]
			pInfo['PE']['ImageOptionalHeader']['MinorOperatingSystemVersion'] = struct.unpack("<H",self.binary.read(2))[0]
			pInfo['PE']['ImageOptionalHeader']['MajorImageVersion'] = struct.unpack("<H",self.binary.read(2))[0]
			pInfo['PE']['ImageOptionalHeader']['MinorImageVersion'] = struct.unpack("<H",self.binary.read(2))[0]
			pInfo['PE']['ImageOptionalHeader']['MajorSubsystemVersion'] = struct.unpack("<H",self.binary.read(2))[0]
			pInfo['PE']['ImageOptionalHeader']['MinorSubsystemVersion'] = struct.unpack("<H",self.binary.read(2))[0]
			pInfo['PE']['ImageOptionalHeader']['Win32VersionValue'] = struct.unpack("<I",self.binary.read(4))[0]
			pInfo['PE']['ImageOptionalHeader']['SizeOfImage'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['SizeOfHeaders'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['CheckSum'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['Subsystem'] = hex(struct.unpack("<H",self.binary.read(2))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DllCharacteristics'] = hex(struct.unpack("<H",self.binary.read(2))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['SizeOfStackReserve'] = hex(struct.unpack(formatz,self.binary.read(bytez))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['SizeOfStackCommit'] = hex(struct.unpack(formatz,self.binary.read(bytez))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['SizeOfHeapReserve'] = hex(struct.unpack(formatz,self.binary.read(bytez))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['SizeOfHeapCommit'] = hex(struct.unpack(formatz,self.binary.read(bytez))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['LoaderFlags'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['NumberOfRvaAndSizes'] = struct.unpack("<I",self.binary.read(4))[0]
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures'] = OrderedDict()
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['ExportDirectoryRVA'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['ExportDirectorySize'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['ImportDirectoryRVA'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['ImportDirectorySize'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['ResourceDirectoryRVA'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['ResourceDirectorySize'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['ExceptionDirectoryRVA'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['ExceptionDirectorySize'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['SecurityDirectoryRVA'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['SecurityDirectorySize'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['RelocationDirectoryRVA'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['RelocationDirectorySize'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['DebugDirectoryRVA'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['DebugDirectorySize'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['ArchitechtureDirectoryRVA'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['ArchitechtureDirectorySize'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['GlobalPtr'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['Reserved'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['TLSDirectoryRVA'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['TLSDirectorySize'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['ConfigurationDirectoryRVA'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['ConfigurationDirectorySize'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['BoundImportDirectoryRVA'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['BoundImportDirectorySize'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['ImportAddressTableDirectoryRVA'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['ImportAddressTableDirectorySize'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['DelayImportDirectoryRVA'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['DelayImportDirectorySizes'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['CLRRuntimeHeaderRVA'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['CLRRuntimeHeaderSize'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['Reserved1'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['PE']['ImageOptionalHeader']['DirectoryStructures']['Reserved2'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
			pInfo['Sections'] = OrderedDict()
			#starting section enumeration
			sections = int(pInfo['PE']['TotalSections'])
			for i in range(0,sections):
				name = self.convert_hex_to_ascii(struct.unpack("<Q",self.binary.read(8))[0]).rstrip('L')
				data = OrderedDict()
				data['VirtualSize'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
				data['VirtualAddress'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
				data['RawSize'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
				data['RawAddress'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
				data['PointerToRelocations'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
				data['PointerToLinenumbers'] = struct.unpack("<I",self.binary.read(4))[0]
				data['NumberOfRelocations'] = struct.unpack("<H",self.binary.read(2))[0]
				data['NumberOfLinenumbers'] = struct.unpack("<H",self.binary.read(2))[0]
				data['Characteristics'] = hex(struct.unpack("<I",self.binary.read(4))[0]).rstrip('L')
				pInfo['Sections'][name] = data


	def print_string_hex(self, str):
		for c in str:
			return "0x%02x " % (c)

		
	def disasm_shellcode(self,shellcode=None,mode=None):
		CODE = shellcode.replace(' ','').replace('\\x', '').decode('hex')
		if not mode:
			mode = ArchTypes[self.PE_SIG]
		print '\t\t------>Disassembly<------\n'
		ARCH = {'x86':CS_ARCH_X86}
		MODE = {'16':CS_MODE_16, '32':CS_MODE_32, '64':CS_MODE_64}
		md = Cs(ARCH["x86"], MODE[mode])
		ss = md.disasm(CODE, 1)
		md.detail = True
		for i in ss:
			a = ""
			for z in i.opcode:
				if hex(z) != "0x0":
					a += hex(z).replace('0x','')
			print '0x%x:\t%s      \t%s %s' % (i.address, a+hex(i.modrm).replace('0x','').replace('0',''),i.mnemonic, i.op_str)
			a=""


	def disasm_file(self,section=None,startOffset=None,endOffset=None,length=None,mode=str(None),inline=None):
		file = self.FILE
		if endOffset:
			length = int(endOffset) - int(startOffset)
		if section and len(section) >= 1:
			startOffset = int(self.json(isdict=1)["SECTIONS"][section]["RawAddress"]["value"],16)
		if pInfo:
			mode = int(ArchTypes[self.PE_SIG])
			if not length:
				length = 200

		bytez = int(length)
		seek = int(startOffset)

		with open(file,'rb') as f:
				if seek:
					f.seek(seek)
				buffer = f.read(bytez)

		buffer = binascii.hexlify(buffer)
		if inline:
			print buffer[:200]
			return
		if section:
			self.hexDump(buffer,bytez=seek)
		else:
			self.hexDump(buffer)
		self.disasm_shellcode(shellcode=buffer,mode=str(mode))


	def chunks(self,l,n):
		n = max(1, n)
		return (l[i:i+n] for i in xrange(0, len(l), n))


	def hexDump(self,data,bytez=0,section=None):
		print;print "\t\t------->Hex Dump<-------";print
		print "Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
		data = list(self.chunks(data[:320],32))
		offset = bytez
		for each in data:
			x = ' '.join(each[i:i+2] for i in range(0, len(each), 2))
			printspace = " "*(10-len(hex(offset)))
			print hex(offset) + printspace + x
			offset += 16
		print


x = "/Users/username/Desktop/PE.exe"
# a = peinfo(x)

# a.checkBinary()
# a.overview()
# a.exportList()
# print a.exportList("lstrlenW")

# print a.json()

# a.disasm_file(startOffset=0x200,length=100)
# a.disasm_file(section=".text")
# a.disasm_file(startOffset=0x200,length=0x400,mode=32)

# a = peinfo().hexDump("5589e583ec18895df88b550831db89758b0231f68b003d910000c077433d8d00c0725bbe01000000c704240800000031")

# a.find_all_caves()

# a.disasm_shellcode("5589e583ec18895df88b550831db89758b0231f68b003d910000c077433d8d00c0725bbe01000000c704240800000031","32")

# a.printOut()
