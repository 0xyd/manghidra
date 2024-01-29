import struct
from dataclasses import dataclass, field
from typing import TypeVar, Optional, Iterator

## Program module must be imported 
from Program import ProgramProxy

from ghidra.program.model import Register
from ghidra.app.emulator import EmulatorHelper
from ghidra.util.task import ConsoleTaskMonitor

## Type hints
from Program import Address

T = TypeVar('T', int, float, str)

def struct_formatter(f):
	def wrapper(
		obj:CodeEmulator, 
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

		if 'value' in kwargs:
			value = kwargs['value']
			f(obj, formatStr, is_little, address, value)
		else:
			f(obj, formatStr, is_little, address)

	return wrapper

@dataclass
class CodeEmulator: 
	"""
	Run code emulation in Ghidra.
	"""
	arch:str = field(default='x86')
	proxy:ProgramProxy = field(default=None)
	helper:EmulatorHelper = field(default=None)
	monitor:ConsoleTaskMonitor = field(default=None)
	pc:Register = field(default=None)
	framePtr:str = field(default='RBP')
	stackPtr:str = field(default='RSP')
	startAddr:Optional[Address] = field(default=None)
	endAddr:Optional[Address] = field(default=None)

	def __post_init__(self):
		self.helper = EmulatorHelper(self.proxy.prog)
		self.pc = self.helper.getPCRegister()
		self.monitor = ConsoleTaskMonitor()

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

	def set_end(self, offset:int):
		"""
		Set the address where the emulation ends.

		"""
		
		self.endAddr = self.proxy.get_addr(offset)

	def get_registers(self):
		pass

	def read_memory(
		self, 
		dtype:str, 
		is_little:bool,
		address:int):
		pass

	def write_memory(
		self, 
		dtype:str, 
		is_little:bool,
		address:int, 
		value:T):
		pass

	def run(
		self, 
		step_limit:Optional[int]=None) -> Iterator[Address]:

		step = 0
		while self.monitor.isCancelled() is False:

			currentAddr = self.helper.getExecutionAddress()
			yield currentAddr

			if currentAddr == self.endAddr:
				return

			success = self.helper.step(self.monitor)
			if not success:
				lastErr = self.helper.getLastError()
				print(f"Emulation error: {lastError}")
				return

			step += 1
			if step_limit:
				print(f"Reach step limit: {step_limit}")
				return

