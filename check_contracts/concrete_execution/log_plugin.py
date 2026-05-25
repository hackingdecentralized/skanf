from collections import defaultdict
from ethpwn import *

from ethpwn.ethlib.evm.plugins.base import BaseAnalysisPlugin
from ethpwn.ethlib.evm.plugins.utils import *
from ethpwn.ethlib.utils import normalize_contract_address


class LogPlugin(BaseAnalysisPlugin):

    name = "transaction_log"

    def __init__(self, target_contract=None, new_caller=None, new_origin=None, overwrite_caller=False, overwrite_origin=False):
        super().__init__()

        self.target_contract = normalize_contract_address(target_contract)
        self.new_caller = normalize_contract_address(new_caller)
        self.new_origin = normalize_contract_address(new_origin)
        self.overwrite_caller = overwrite_caller
        self.overwrite_origin = overwrite_origin
        self.call_pcs = []
        self.current_branches = ['0x0']
        self.counts = defaultdict(int)
        self.sequences = []

    def pre_opcode_hook(self, opcode, computation):
        pc = hex(computation.code.program_counter-1)
        self.counts[pc] += 1
        self.sequences.append(pc)

        curr_contract = normalize_contract_address(computation.msg.code_address)
        if opcode.mnemonic == 'CALL' and curr_contract == self.target_contract:
            self.call_pcs.append((pc, self.current_branches[::]))
        if opcode.mnemonic == 'JUMPDEST' and curr_contract == self.target_contract:
            self.current_branches.append(pc)
        # if opcode.mnemonic == 'CALLDATALOAD' and curr_contract == self.target_contract:
        #     print(pc, f"CALLDATALOAD: {computation._stack.values[-1]}")


    def post_opcode_hook(self, opcode, computation):
        curr_contract = normalize_contract_address(computation.msg.code_address)

        if curr_contract == self.target_contract and computation.msg.depth == 0:
            if opcode.mnemonic == 'CALLER':
                current_caller_type, _ = computation._stack.values[-1]
                
                if self.overwrite_caller:
                    if current_caller_type == int:
                        computation._stack.values[-1] = (
                            int,
                            int(self.new_caller, 16)
                        )
                    else:
                        computation._stack.values[-1] = (
                            bytes,
                            bytes.fromhex(self.new_caller[2:])
                        )
                        
        # rewrite the origin to simulate that the call is from a specific origin
        if opcode.mnemonic == 'ORIGIN':
            current_origin_type, _ = computation._stack.values[-1]

            if self.overwrite_origin:
                if current_origin_type == int:
                    computation._stack.values[-1] = (
                        int,
                        int(self.new_origin, 16)
                    )
                else:
                    computation._stack.values[-1] = (
                        bytes,
                        bytes.fromhex(self.new_origin[2:])
                    )
