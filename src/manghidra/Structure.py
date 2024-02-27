import sys
if 'pyhidra' not in sys.modules:
	import pyhidra
	print("pyhidra.start()")
	pyhidra.start()

from dataclasses import dataclass, field
from typing import Set, List, Dict, Tuple, NewType, TypeVar, Optional

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.block import BasicBlockModel

## Type hints
from manghidra.Program import ProgramProxy
from manghidra.Program import Address, FuncName

BlockName = NewType('BlockName', str)
AddressList = List[Address]
InstructionList = List[int]
BlockAttr = NewType('BlockAttribute', str)
BlockData = TypeVar(
	'BlockData', 
	# BlockName, 
	FuncName, 
	AddressList, 
	InstructionList)
BlockMeta = Dict[BlockAttr, BlockData]
BlockAddrTuple = Tuple[Address, Address, BlockName]
Edge = Tuple[BlockName, BlockName]


@dataclass
class ControlflowGraph(ProgramProxy):

	funcBlocks:Dict[FuncName, List[BlockName]] = field(
		default_factory=dict)
	blocks:Dict[BlockName, BlockMeta] = field(
		default_factory=dict)

	## 20240226
	## addr2Block (Address to Block) is a list structure
	## I used to locate where the instruction is.
	## This structure shall be build in a tree for 
	## better search speed but at the moment I keep it this way.
	addr2Block:List[BlockAddrTuple] = field(
		default_factory=list)

	## Attribute to store all the edges
	allEdges:Set[Edge] = field(default_factory=set)

	def __post_init__(self):

		super().__post_init__()
		self.monitor = ConsoleTaskMonitor()
		self.basicBlockModel = BasicBlockModel(self.prog)

		for funcName, blockName, blockData in self._iter_blocks():
			if funcName in self.funcBlocks:
				self.funcBlocks[funcName].append(blockName)
			else:
				self.funcBlocks[funcName] = [blockName]

			self.blocks[blockName] = blockData

			self.addr2Block.append((
				blockData['min_addr'],
				blockData['max_addr'],
				blockName
				))

			for dst in blockData['destinations']:
				self.allEdges.add((blockName, dst))

		self.addr2Block.sort(key=lambda x: x[0])



	def _iter_blocks(self) -> Tuple[
		FuncName, BlockName, BlockMeta]:
		"""
		Iterate all blocks in each function.

		"""

		for func in self.funcMgr.getFunctions(True):

			funcName = func.getName()
			funcBody = func.getBody()
			blocksIter = self.basicBlockModel.getCodeBlocksContaining(
					funcBody, 
					self.monitor)

			for block in blocksIter:
				blockName = block.name
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
					srcAddrs.append(src.sourceAddress)

				dstAddrs = []
				dstIterator = block.getDestinations(self.monitor)
				while dstIterator.hasNext():
					dst = dstIterator.next()
					dstAddrs.append(dst.destinationAddress)

				data = {
					'belongs_to': funcName,
					'min_addr': minAddr,
					'max_addr': maxAddr,
					'sources': srcAddrs,
					'destinations': dstAddrs,
					'instructions': instructions
				}

				yield (funcName, blockName, data)


	def get_blockname_by_addr(
		self, 
		addr:int) -> Optional[str]:
		'''
		Get the block name by the address value
		'''
		for addrMin, addrMax, blockName in self.addr2Block:
			
			addrMin = addrMin.getOffset()
			addrMax = addrMax.getOffset()
			if addr >= addrMin and addr < addrMax:
				return blockName

		return None
