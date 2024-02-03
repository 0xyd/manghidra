from dataclasses import dataclass, field
from typing import List, Dict, NewType, TypeVar

from Program import ProgramProxy

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.block import BasicBlockModel

## Type hints
from Program import Address, FuncName

BlockName = NewType('BlockName', str)
BlockMeta = NewType('BlockMeta', str)
AddressList = List[Address]
InstructionList = List[int]
BlockData = TypeVar(
	'BlockData', 
	BlockName, 
	FuncName, 
	AddressList, 
	InstructionList)

@dataclass
class ControlflowGraph(ProgramProxy):

	blocks:Dict[BlockMeta, BlockData] = field(default=None)

	def __post_init__(self):
		super().__post_init__()
		self.monitor = ConsoleTaskMonitor()
		self.basicBlockModel = BasicBlockModel(self.prog)

	def _iter_blocks(self):

		for func in self.funcMgr.getFunctions(True):
			funcBody = func.getBody()
			blocksIter = self.basicBlockModel.getCodeBlocksContaining(
					funcBody, 
					self.monitor)

			for block in blocksIter:
				minAddr = block.minAddress
				maxAddr = block.maxAddress
				addrSet = block.intersectRange(
					minAddr,
					maxAddr)
				code = self.listing.getCodeUnits(
					addrSet, 
					True)

				instructions = []
				for inst in code:
					instAddr = inst.getAddress()
					instStr  = inst.toString()
					instructions.append(
						(instAddr, instStr))

				srcAddrs = []
				srcIterator = block.getSources(self.monitor)
				while srcIterator.hasNext():
					src = srcIterator.next()
					srcAddrs.append(src)

				destAddrs = []
				dstIterator = block.getDestinations(self.monitor)
				while dstIterator.hasNext():
					dst = dstIterator.next()
					destAddrs.append(dst)

				yield {
					'name': block.name,
					'min_addr': minAddr,
					'max_addr': maxAddr,
					'sources': srcAddrs,
					'destinations': destAddrs,
					'instructions': instructions
				}

