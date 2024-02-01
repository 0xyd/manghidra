import struct
from dataclasses import dataclass, field
from typing import List, Dict, NewType, TypeVar, Optional, Iterator, Callable

## Program module must be imported 
from Program import ProgramProxy

from ghidra.program.model.lang import Register
from ghidra.app.emulator import EmulatorHelper
from ghidra.util.task import ConsoleTaskMonitor

## Type hints
from Program import Address, AddressValue

T = TypeVar('T', int, float, str, List[int], List[float], List[str])
RegisterName = NewType('RegisterName', str)

def struct_formatter(f):
	def wrapper(
		obj:Callable, 
		dtype:str, 
		is_little:bool, 
		addr:int,
		**kwargs):

		formatStr = ''
		if is_little:
			formatStr += '<'
		else:
			formatStr += '>'

		### The length of formatStr is related how many elements in value 
		### are going to pack or unpack.
		value = None
		if 'value' in kwargs:
			value = kwargs['value']
		
		dataLen = 1
		if isinstance(value, list):
			dataLen = len(value)

		if dtype == 'uint8_t':
			formatStr += 'B' * dataLen
		elif dtype == 'int8_t':
			formatStr += 'b' * dataLen
		elif dtype == 'uint16_t':
			formatStr += 'H' * dataLen
		elif dtype == 'int16_t':
			formatStr += 'h' * dataLen
		elif dtype == 'uint32_t':
			formatStr += 'I' * dataLen
		elif dtype == 'int32_t':
			formatStr += 'i' * dataLen
		elif dtype == 'uint64_t':
			formatStr += 'Q' * dataLen
		elif dtype == 'int64_t':
			formatStr += 'q' * dataLen

		## Python complains:
		## struct.err: bad char in struct object
		# elif dtype == 'size_t':
		# 	formatStr += 'N' * dataLen

		else:
			raise NotImplemented(
				f'{dtype} is not implemented yet.')

		num_bytes = 1 * dataLen
		if dtype in ['uint16_t', 'int16_t']:
			num_bytes = 2 * dataLen
		elif dtype in ['uint32_t', 'int32_t']:
			num_bytes = 4 * dataLen
		elif dtype in ['uint64_t', 'int64_t']:
			num_bytes = 8 * dataLen

		if value:
		# if 'value' in kwargs:
		# 	value = kwargs['value']
			r = f(
				obj, 
				formatStr, 
				is_little, 
				addr, 
				value, 
				num_bytes=num_bytes)
		else:
			r = f(
				obj, 
				formatStr, 
				is_little, 
				addr, 
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
		elif self.arch == 'arm':
			## Frame pointer (R11) contains the return address
			## of a calling function.
			self.framePtr = 'r11' 
			## Stack pointer (R13) register contains the address
			## of the top of a stack
			self.stackPtr = 'sp'
		else:
			raise NotImplemented(
				f'{self.arch} is not implemented yet.')

	def read_stack_ptr(self) -> int:
		return int(self.read_register(self.stackPtr))

	def read_base_ptr(self) -> int:
		return int(self.read_register(self.framePtr))

	def set_start(
		self, 
		pc_addr:int, 
		frame_addr:int, 
		stack_addr:int):
		"""
		Set the addresses for pc register, base and stack pointers.
		"""
		self.write_register(self.stackPtr, stack_addr)
		self.write_register(self.framePtr, frame_addr)
		self.write_register(self.pc, pc_addr)
		# self.helper.writeRegister(self.stackPtr, stack_addr)
		# self.helper.writeRegister(self.framePtr, frame_addr)
		# self.helper.writeRegister(self.pc, pc_addr)

	def set_end(self, addr:int):
		"""
		Set the address where the emulation ends.

		"""
		self.endAddr = self.get_addr(addr)

	def read_register(
		self, 
		reg_name:RegisterName) -> AddressValue:

		if reg_name == 'pc':
			r = self.helper.readRegister(self.pc)
		else:
			r = self.helper.readRegister(reg_name)

		return r.intValue()

	def write_register(
		self, 
		reg_name:RegisterName,
		value:int):

		self.helper.writeRegister(reg_name, value)

	@struct_formatter
	def read_memory(
		self, 
		dtype:str, 
		is_little:bool,
		addr:Address,
		**kwargs:int):

		num_bytes = kwargs['num_bytes']

		r = self.helper.readMemory(
			addr, 
			num_bytes)
		r = struct.unpack(dtype, r)
		return r

	@struct_formatter
	def write_memory(
		self, 
		dtype:str, 
		is_little:bool,
		addr:Address, 
		value:T,
		**kwargs:int) -> None:
	
		if isinstance(value, list):
			value = struct.pack(dtype, *value)
		else:
			value = struct.pack(dtype, value)

		self.helper.writeMemory(addr, value)


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