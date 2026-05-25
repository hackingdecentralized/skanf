from ethpwn.ethlib.evm.plugins.base import BaseAnalysisPlugin
from ethpwn.ethlib.evm.plugins.utils import *
from ethpwn.ethlib.utils import normalize_contract_address


class CheckPlugin(BaseAnalysisPlugin):

    name = "origin_sender_checker"

    def __init__(self, calltacid, target_contract=None, new_caller=None, new_origin=None, overwrite_caller=False, overwrite_origin=False):
        super().__init__()
        self.calltacid = calltacid
        self.call_is_reachable = False

        self.target_contract = normalize_contract_address(target_contract)
        self.new_caller = normalize_contract_address(new_caller)
        self.new_origin = normalize_contract_address(new_origin)
        self.overwrite_caller = overwrite_caller
        self.overwrite_origin = overwrite_origin

    def pre_opcode_hook(self, opcode, computation):
        pc = hex(computation.code.program_counter-1)

        if opcode.mnemonic == 'CALL':
            print(opcode.mnemonic, pc, self.calltacid)
        if opcode.mnemonic == 'CALL' and self.calltacid.startswith(pc):
            self.call_is_reachable = True


    def post_opcode_hook(self, opcode, computation):
        curr_contract = normalize_contract_address(computation.msg.code_address)

        if curr_contract == self.target_contract:
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
