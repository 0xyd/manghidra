from pathlib import Path
from dataclasses import dataclass, field
from contextlib import _GeneratorContextManager
from typing import List, Tuple, Dict, Iterator, NewType, Optional

from __init__ import start

pyhidra = start()

from ghidra.program.flatapi import FlatProgramAPI 
from ghidra.program.database import ProgramDB
from ghidra.program.database.function import FunctionManagerDB
from ghidra.program.model.listing import ListingStub, FunctionIterator
from ghidra.program.model.address import GenericAddress, AddressSpace

# Customized Type hints
ContextManager = _GeneratorContextManager
Address = GenericAddress
AddressRange = Tuple[int, int]
VarName = NewType('VarName', str)
VarStackOffset = NewType('VarStackOffset', int)
VarInfo = Dict[VarName, VarStackOffset]
VarList = List[VarInfo]
FuncName = NewType('FuncName', str)
FuncMeta = Tuple[FuncName, AddressRange, Optional[VarList]]
FuncData = Tuple[AddressRange, Optional[VarList]]

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
	funcMeta:Dict[FuncName, FuncData] = field(default_factory=dict)

	def __post_init__(self):
		self.context = pyhidra.open_program(self.binaryPath)
		self.api = self.context.__enter__()
		self.prog = self.api.getCurrentProgram()
		self.listing = self.prog.getListing()
		self.funcMgr = self.prog.getFunctionManager()
		self.progAddrSpace = self.prog.getAddressFactory().getDefaultAddressSpace()

		for funcName, addrRange, var in self.list_functions():
			self.funcMeta[funcName] = (addrRange, var)

	def terminate(self):
		self.context.__exit__(None, None, None)

	def get_addr(self, offset:int) -> Address:
		"""
		Get the address of a program by offset.
		"""
		return self.progAddrSpace.getAddress(offset)

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

## Code for testing only
# p = ProgramProxy(binaryPath=Path('main.o'))
# a = p.get_addr(0x0)
# print(a)
# # print(type(a))
# p.list_functions()
# p.terminate()