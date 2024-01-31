import struct
from dataclasses import dataclass, field
from typing import List, Dict, TypeVar, Optional, Iterator, Callable

## Program module must be imported 
from Program import ProgramProxy

from ghidra.program.model.lang import Register
from ghidra.app.emulator import EmulatorHelper
from ghidra.util.task import ConsoleTaskMonitor

## Type hints
from Program import Address, AddressValue

T = TypeVar('T', int, float, str)

def struct_formatter(f):
	def wrapper(
		obj:Callable, 
		dtype:str, 
		is_little:bool, 
		address:int,
		**kwargs):

		formatStr = ''
		if is_little:
			formatStr += '<'
		else:
			formatStr += '>'

		if dtype == 'uint16_t':
			formatStr += 'H'
		elif dtype == 'int16_t':
			formatStr += 'h'
		elif dtype == 'uint32_t':
			formatStr += 'I'
		elif dtype == 'int32_t':
			formatStr += 'i'
		elif dtype == 'uint64_t':
			formatStr += 'Q'
		elif dtype == 'int64_t':
			formatStr += 'q'

		else:
			raise NotImplemented(
				f'{dtype} is not implemented yet.')

		num_bytes = 1
		if dtype in ['uint16_t', 'int16_t']:
			num_bytes = 2
		elif dtype in ['uint32_t', 'int32_t']:
			num_bytes = 4
		elif dtype in ['uint64_t', 'int64_t']:
			num_bytes = 8

		if 'value' in kwargs:
			value = kwargs['value']
			r = f(
				obj, 
				formatStr, 
				is_little, 
				address, 
				value, 
				num_bytes=num_bytes)
		else:
			r = f(
				obj, 
				formatStr, 
				is_little, 
				address, 
				num_bytes=num_bytes)

		return r

	return wrapper

@dataclass
class CodeEmulator(ProgramProxy): 
	"""
	Run code emulation in Ghidra.
	"""
	arch:str = field(default='x86')
	# proxy:ProgramProxy = field(default=None)
	helper:EmulatorHelper = field(default=None)
	monitor:ConsoleTaskMonitor = field(default=None)
	pc:Register = field(default=None)
	framePtr:Optional[str] = field(default=None)
	stackPtr:Optional[str] = field(default=None)
	startAddr:Optional[Address] = field(default=None)
	endAddr:Optional[Address] = field(default=None)
	# regList:List[T] = field(default_factory=list)

	def __post_init__(self):

		super().__post_init__()
		self.helper = EmulatorHelper(self.prog)
		self.pc = self.helper.getPCRegister()
		self.monitor = ConsoleTaskMonitor()
		if self.arch == 'x86':
			self.framePtr = 'RBP'
			self.stackPtr = 'RSP'
		else:
			raise NotImplemented(
				f'{self.arch} is not implemented yet.')

	def set_start(
		self, 
		pc_addr:int, 
		frame_addr:int, 
		stack_addr:int):
		"""
		Set the addresses for pc register, base and stack pointers.
		"""

		self.helper.writeRegister(self.stackPtr, stack_addr)
		self.helper.writeRegister(self.framePtr, frame_addr)
		self.helper.writeRegister(self.pc, pc_addr)

	def set_end(self, addr:int):
		"""
		Set the address where the emulation ends.

		"""
		self.endAddr = self.get_addr(addr)

	def read_register(
		self, 
		reg_name:str) -> AddressValue:

		if reg_name == 'pc':
			r = self.helper.readRegister(self.pc)
		else:
			r = self.helper.readRegister(reg_name)

		return r.intValue()

	@struct_formatter
	def read_memory(
		self, 
		dtype:str, 
		is_little:bool,
		address:int,
		**kwargs:int):

		num_bytes = kwargs['num_bytes']

		r = self.helper.readMemory(
			address, 
			num_bytes)
		r = struct.unpack(dtype, r)
		return r

	@struct_formatter
	def write_memory(
		self, 
		dtype:str, 
		is_little:bool,
		address:int, 
		value:T,
		**kwargs:int) -> None:
		
		value = struct.pack(dtype, value)

		self.helper.writeMemory(address, value)


	## We will revisit this later.
	# def read_stack(self) -> Dict[str, Address]:
	# 	"""
	# 	Read data in the current stack
	# 	when pc just executes instruction in chosen address
	# 	"""
	# 	fp = self.helper.readRegister(self.framePtr)
	# 	sp = self.helper.readRegister(self.stackPtr)
	# 	pc = self.helper.readRegister(self.pc)
	# 	print(hex(pc.intValue()))
	# 	print(self.proxy.get_vars_by_addr(
	# 		addr=pc.intValue()))

	# 	### The Ghidra say local_c is RBP-0x4
	# 	print(fp.intValue() - 0x4)
	# 	### But there is another info say Stack - 0xc
	# 	print(sp.intValue() - 0xc)
	# 	# print('type(fp):', type(fp))
	# 	# print('fp:', fp)
	# 	# print('type(sp):', type(sp))
	# 	# print('sp:', sp)
	# 	# print('type(pc):', type(pc))
	# 	# print('pc:', pc)


	def run(
		self, 
		step_limit:Optional[int]=None) -> Iterator[Address]:

		step = 0
		while self.monitor.isCancelled() is False:

			# print(f'step {step}')
			# r = self.helper.readRegister('RBP')
			# print(f'RBP: {hex(int(r.toString()))}')
			# r = self.helper.readRegister('RSP')
			# print(f'RSP: {hex(int(r.toString()))}')

			currentAddr = self.helper.getExecutionAddress()
			yield currentAddr

			if currentAddr == self.endAddr:
				print('reach endAddr:', self.endAddr)
				return

			success = self.helper.step(self.monitor)
			if not success:
				lastErr = self.helper.getLastError()
				print(f"Emulation error: {lastError}")
				return

			step += 1
			if step == step_limit:
				print(f"Reach step limit: {step_limit}")
				return

	def terminate(self) -> None:
		self.helper.dispose()
		super().terminate()