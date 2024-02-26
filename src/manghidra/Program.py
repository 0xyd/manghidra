# import sys
# if 'pyhidra' not in sys.modules:
# 	import pyhidra
# 	print("pyhidra.start()")
# 	pyhidra.start()

from pathlib import Path
from dataclasses import dataclass, field
from contextlib import _GeneratorContextManager
from typing import List, Tuple, Dict, Iterator, NewType, Optional

# from __init__ import start

# ## Prevent pyhidra be initialized twice.
# if 'pyhidra' in globals():
# 	print('pyhidra already started')
# else:
# 	import pyhidra
# 	pyhidra.start()
# 	print('pyhidra starts')

from ghidra.program.flatapi import FlatProgramAPI 
from ghidra.program.database import ProgramDB
from ghidra.program.database.function import FunctionManagerDB
from ghidra.program.model.listing import ListingStub, FunctionIterator
from ghidra.program.model.address import GenericAddress, AddressSpace

# Customized Type hints
ContextManager = _GeneratorContextManager
Address = GenericAddress
AddressValue = NewType('AddressValue', int)
AddressRange = Tuple[Address, Address]
VarName = NewType('VarName', str)
VarStackOffset = NewType('VarStackOffset', int)
VarInfo = Dict[VarName, VarStackOffset]
VarList = List[VarInfo]
FuncName = NewType('FuncName', str)
FuncMeta = Tuple[FuncName, AddressRange, Optional[VarList]]
FuncData = Tuple[AddressRange, Optional[VarList]]
AddressRangeFunc = Tuple[AddressRange, FuncName]

@dataclass
class ProgramProxy():
	"""
	The below code will cause error:
	TypeError: Java classes cannot be extended in Python

	class Program(ProgramAPI):pass

	Therefore, we create a proxy instead.
	"""
	context:ContextManager = field(default=None)
	api:FlatProgramAPI  = field(default=None)
	binaryPath:Path = field(default=None)
	prog:ProgramDB  = field(default=None)
	listing:ListingStub = field(default=None)
	funcMgr:FunctionManagerDB  = field(default=None)
	progAddrSpace:AddressSpace = field(default=None)
	# funcMeta:Dict[FuncName, FuncData] = field(
	# 	default_factory=dict)
	funcAddrRange:Dict[FuncName, AddressRange] = field(
		default_factory=dict)
	funcEntry:Dict[FuncName, AddressValue] = field(
		default_factory=dict)
	addrRangeVars:Dict[AddressRange, VarInfo] = field(default_factory=dict)
	### List is kinda slow for traverse.
	### Shall consider to implement a version with tree
	addrRanges:List[AddressRangeFunc] = field(
		default_factory=list)

	def __post_init__(self):
		self.context = pyhidra.open_program(self.binaryPath)
		self.api = self.context.__enter__()
		self.prog = self.api.getCurrentProgram()
		self.listing = self.prog.getListing()
		self.funcMgr = self.prog.getFunctionManager()
		self.progAddrSpace = self.prog.getAddressFactory().getDefaultAddressSpace()

		for funcName, addrRange, var in self.list_functions():
			self.funcAddrRange[funcName] = addrRange
			self.funcEntry[funcName] = addrRange[0].offset
			self.addrRangeVars[addrRange] = var
			self.addrRanges.append((addrRange, funcName))
		self.addrRanges.sort(key=lambda x: x[0][0].offset)
		
	def terminate(self):
		self.context.__exit__(None, None, None)

	def get_addr(self, offset:int) -> Address:
		"""
		Get the address of a program by offset.
		"""
		return self.progAddrSpace.getAddress(offset)


	def get_func_entry(
		self, 
		func_name:str) -> AddressValue:
		"""
		Get the entry point of a function
		"""
		return self.funcEntry[func_name]

	def list_functions(self) -> Iterator[FuncMeta]:
		"""
		List names of functions, their addresses' range,
		and their variables's stack offset.
		"""
		for f in self.funcMgr.getFunctions(True):

			n = f.getName()
			b = f.getBody()
			fmaxAddr = b.getMaxAddress()
			fminAddr = b.getMinAddress()

			var = {}
			for v in f.getLocalVariables():
				vn = v.getName()
				offset = v.getStackOffset()
				var[vn] = offset

			yield (n, (fminAddr, fmaxAddr), var)

	### List is slow. Shall be changed in future.
	def _traverse_addrrange(self) -> Iterator[AddressRangeFunc]:
		for r in self.addrRanges:
			yield r

	def get_vars_by_addr(self, addr:int) -> VarInfo:
		"""
		Get name and offset of variables (local) in a stack
		"""
		for r in self._traverse_addrrange():
			r0 = r[0][0]
			r1 = r[0][1]
			if (addr >= r0.offset) and (
				addr <= r1.offset):
				print('r:', r)
				print('r0.offset:', r0.offset)
				print('r1.offset:', r1.offset)
				print(addr)
				return self.addrRangeVars[(r0, r1)]
		return {}
		

## Code for testing only
# p = ProgramProxy(binaryPath=Path('main.o'))
# a = p.get_addr(0x0)
# print(a)
# # print(type(a))
# p.list_functions()
# p.terminate()