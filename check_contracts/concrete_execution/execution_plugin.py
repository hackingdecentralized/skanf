import networkx as nx

from greed.exploration_techniques import ExplorationTechnique
from greed.solver.shortcuts import *
from greed.TAC.gigahorse_ops import *
from greed.TAC.math_ops import *
from greed.TAC.mem_ops import *
from greed.TAC.special_ops import *


"""
Path Limiter Technique
========================
This module implements a path limiter technique for contract exploration, which limits the exploration to a specific path defined by a list of statement IDs (traces).
The technique will halt the exploration if the current path does not match the specified traces.
"""
class PathLimiter(ExplorationTechnique):
    """
    Path Limiter is a technique that limits the exploration of the contract to a specific path.
    """

    def __init__(self, traces):
        super().__init__()
        self.traces = traces

        self._name = "Path Limiter"

    def setup(self, simgr):
        """
        Setup the technique.
        Args:
            simgr: the simulation manager
        """
        for state in simgr.states:
            state.globals["traces"] = []

    
    def check_state(self, simgr, state):
        tmp_traces = state.globals["traces"] + [state.curr_stmt.id]
        if self.traces[:len(tmp_traces)] != tmp_traces:
            state.halt = True
        else:
            state.globals["traces"] = tmp_traces

        return state


class MemoryNode:
    def __init__(self, source, offset, size, type):
        self.source = source
        self.offset = offset
        self.size = size
        self.type = type  # e.g., "stack", "calldata"



"""
Taint Analysis Technique
========================
This module implements a taint analysis technique for contract exploration, which tracks the flow of data through the contract.
It identifies the source and sink of dataflow and builds a directed graph to represent the flow.
"""
class DataflowTracer(ExplorationTechnique):
    """
    Dataflow Tracer is a technique that traces the dataflow of the contract.
    """

    def __init__(self):
        super().__init__()
        self.name = "Dataflow Tracer"
        self.memory_mapping = [

        ]


    def check_data_flow(self, state):
        current_stmt = state.curr_stmt
        type_of_stmt = type(current_stmt)
        if type(current_stmt) == TAC_Calldataload:
            sink = current_stmt.res1_var
            if current_stmt.arg1_val is not None and is_concrete(current_stmt.arg1_val):
                source = current_stmt.arg1_val.value
            else:
                source = current_stmt.arg1_var
            state.globals["calldata_nodes"].append((source, sink))
        
        elif type_of_stmt in set([TAC_Add, TAC_Sub, TAC_Mul, TAC_Div, TAC_Mod, TAC_Sdiv, TAC_Smod, TAC_Exp, TAC_Signextend]):
            sink = current_stmt.res1_var
            for value, source in zip([current_stmt.arg1_val, current_stmt.arg2_val], [current_stmt.arg1_var, current_stmt.arg2_var]):
                if value is  None or not is_concrete(value):
                    state.globals["dataflow"].add_edge(source, sink)
        
        elif type_of_stmt in set([TAC_Shl, TAC_Shr, TAC_Sar]):
            sink = current_stmt.res1_var
            for value, source in zip([current_stmt.arg1_val, current_stmt.arg2_val], [current_stmt.arg1_var, current_stmt.arg2_var]):
                if value is None or not is_concrete(value):
                    state.globals["dataflow"].add_edge(source, sink)
        
        elif type_of_stmt in set([TAC_And, TAC_Or, TAC_Xor]):
            sink = current_stmt.res1_var
            for value, source in zip([current_stmt.arg1_val, current_stmt.arg2_val], [current_stmt.arg1_var, current_stmt.arg2_var]):
                if value is  None or not is_concrete(value):
                    state.globals["dataflow"].add_edge(source, sink)
        
        elif type_of_stmt in set([TAC_Not, TAC_Iszero]):
            sink = current_stmt.res1_var
            value = current_stmt.arg1_val
            source = current_stmt.arg1_var
            if value is  None or not is_concrete(value):
                state.globals["dataflow"].add_edge(source, sink)
        
        elif type_of_stmt == TAC_Byte:
            sink = current_stmt.res1_var
            value = current_stmt.arg2_val
            source = current_stmt.arg2_var
            if value is  None or not is_concrete(value):
                state.globals["dataflow"].add_edge(source, sink)
        
        elif type_of_stmt == TAC_Mload:
            offset = state.solver.eval(state.registers[current_stmt.arg1_var])
            sink = current_stmt.res1_var
            for dest_offset, source_offset, size, m_type in self.memory_mapping:
                # from mstore
                if m_type == 'mstore':
                    if offset >= dest_offset and offset < dest_offset + size:
                        # Calculate the source offset in the mstore range
                        state.globals["dataflow"].add_edge(f"m_{dest_offset}", f"m_{offset}")  # Connect mstore to mload
                        break
                # from calldata
                else:
                    if offset >= dest_offset and offset < dest_offset + size:
                        source_offset = offset - dest_offset + source_offset
                        state.globals["calldata_nodes"].append((source_offset, sink))
                        break
            
            state.globals["dataflow"].add_edge(f"m_{offset}", sink)

        elif type_of_stmt == TAC_Mstore or type_of_stmt == TAC_Mstore8:
            source = current_stmt.arg2_var
            sink = current_stmt.arg1_var
            offset_val = state.solver.eval(state.registers[sink])
            state.globals["dataflow"].add_edge(source, f"m_{offset_val}")
            state.globals["memory_nodes"].append(MemoryNode(source, offset_val, 32, "stack"))
            
            self.memory_mapping.append((offset_val, source, 32, 'mstore'))  # Keep track of the memory mapping for Mstore/Mstore8

        elif type_of_stmt == TAC_Calldatacopy:
            source = current_stmt.arg2_var
            sink = current_stmt.arg1_var
            dest_offset = state.solver.eval(state.registers[sink])
            source_offset = state.solver.eval(state.registers[source])
            size = state.solver.eval(state.registers[current_stmt.arg3_var])
            
            state.globals["dataflow"].add_edge(source, sink)
            state.globals["memory_nodes"].append(MemoryNode(source_offset, dest_offset, size, "calldata"))
            state.globals["calldata_nodes"].append((source, sink))

            self.memory_mapping.append((dest_offset, source_offset, size, 'calldata'))

        elif type_of_stmt == TAC_Callprivate:
            target_bb_id = hex(bv_unsigned_value(current_stmt.arg1_val))
            target_bb = state.project.factory.block(target_bb_id)

            args = current_stmt.arg_vars[1:]
            args_alias = target_bb.function.arguments
        
            alias_arg_map = dict(zip(args_alias, args))
            for sink, source in alias_arg_map.items():
                state.globals["dataflow"].add_edge(source, sink)

        elif type_of_stmt == TAC_Phi:
            most_recent_write_instruction_count = -1
            most_recent_write_register_name = None
            current_stmt_block_id = current_stmt.block_id

            # count the times the current block id appears in the trace
            current_block_count = 0
            in_segment = False
            historical_block_ids = [i.block_id for i in state.trace] + [state.curr_stmt.block_id]
            for block_id in historical_block_ids:
                if block_id == current_block_id:
                    if not in_segment:
                        current_block_count += 1
                        in_segment = True
                else:
                    in_segment = False

            for arg_var in current_stmt.arg_vars:
                if arg_var not in state.registers:
                    continue

                reg = state.registers.register(arg_var)
                if reg.last_written_instruction_count > most_recent_write_instruction_count and reg.phi_block_id != (current_stmt_block_id, current_block_count):
                    most_recent_write_instruction_count = reg.last_written_instruction_count
                    most_recent_write_register_name = arg_var

            if most_recent_write_register_name is not None:
                sink = current_stmt.res1_var
                source = most_recent_write_register_name
                state.globals["dataflow"].add_edge(source, sink)

        elif type_of_stmt == TAC_Callprivate:
            target_bb_id = hex(bv_unsigned_value(current_stmt.arg1_val))
            target_bb = state.project.factory.block(target_bb_id)

            # read arg-alias map
            args = current_stmt.arg_vars[1:]
            args_alias = target_bb.function.arguments
            alias_arg_map = dict(zip(args_alias, args))
            for sink, source in alias_arg_map.items():
                state.globals["dataflow"].add_edge(source, sink)
    
        elif type_of_stmt == TAC_Returnprivate:
            callprivate_pc, saved_return_pc, callprivate_return_vars = state.callstack.pop()
            state.callstack.append((callprivate_pc, saved_return_pc, callprivate_return_vars))

            returnprivate_args = current_stmt.arg_vars[1:]
            for sink, source in zip(callprivate_return_vars, returnprivate_args):
                state.globals["dataflow"].add_edge(source, sink)


    def setup(self, simgr):
        for state in simgr.states:
            state.globals["dataflow"] = nx.DiGraph()
            state.globals["calldata_nodes"] = []
            state.globals["memory_nodes"] = []

    
    def check_state(self, simgr, state):
        self.check_data_flow(state)

        # if type(current_stmt) == TAC_Assignment:
        #     state.globals["dataflow"].add_edge(current_stmt.arg1_val.value, current_stmt.arg2_val.value)



"""
Taint Analysis Technique
========================
This module implements a taint analysis technique for contract exploration, which tracks the flow of data through the contract.
It identifies the source and sink of dataflow and builds a directed graph to represent the flow.
"""
class CalldataNode:
    def __init__(self, pos):
        self.pos = pos

class DataflowTracerV2(ExplorationTechnique):
    """
    Dataflow Tracer is a technique that traces the dataflow of the contract.
    """

    def __init__(self):
        super().__init__()
        self.name = "Dataflow Tracer V2"
        self.trace_registers = {}


    def check_data_flow(self, state):
        current_stmt = state.curr_stmt
        type_of_stmt = type(current_stmt)
        if type(current_stmt) == TAC_Calldataload:
            sink = current_stmt.res1_var
            if current_stmt.arg1_val is not None and is_concrete(current_stmt.arg1_val):
                source = current_stmt.arg1_val.value
            else:
                source = current_stmt.arg1_var
                source = state.solver.eval(state.registers[source])

            self.trace_registers[sink] = [CalldataNode(source+i) for i in range(32)]  # Store the calldata node in the register
        
        elif type_of_stmt in set([TAC_Add, TAC_Sub, TAC_Mul, TAC_Div, TAC_Mod, TAC_Sdiv, TAC_Smod, TAC_Exp, TAC_Signextend]):
            sink = current_stmt.res1_var
            for value, source in zip([current_stmt.arg1_val, current_stmt.arg2_val], [current_stmt.arg1_var, current_stmt.arg2_var]):
                if value is None or not is_concrete(value):
                    original_source = self.trace_registers.get(source, [None]*32)  # Get the original source register
                    if all(x is None for x in original_source):
                        self.trace_registers[sink] = self.trace_registers.get(source, [None]*32)
        
        elif type_of_stmt == TAC_Shl:
            sink = current_stmt.res1_var
            shift = state.solver.eval(state.registers[current_stmt.arg1_var])
            if current_stmt.arg2_val is None or not is_concrete(current_stmt.arg2_val):
                shift_bytes = shift % 256 // 8
                value = self.trace_registers.get(current_stmt.arg2_var, [None]*32)
                self.trace_registers[sink] = [None]*32  # Initialize the register with None
                for i in range(32-shift_bytes):
                    self.trace_registers[sink][i] = value[i+shift_bytes] if i+shift_bytes < 32 else None

        elif type_of_stmt in set([TAC_Shr, TAC_Sar]):
            sink = current_stmt.res1_var
            shift = state.solver.eval(state.registers[current_stmt.arg1_var])  # Get the shift value
            if current_stmt.arg2_val is None or not is_concrete(current_stmt.arg2_val):
                shift_bytes = shift % 256 // 8
                value = self.trace_registers.get(current_stmt.arg2_var, [None]*32)
                self.trace_registers[sink] = [None]*32
                for i in range(32-shift_bytes):
                    if i+shift_bytes < 32:
                        self.trace_registers[sink][i+shift_bytes] = value[i]
        
        elif type_of_stmt == TAC_And:
            sink = current_stmt.res1_var
            values = [(1<<(8*i))-1 for i in range(1, 33)]  # Bit positions for 32 bytes
            flag = False
            if current_stmt.arg1_val is not None and is_concrete(current_stmt.arg1_val) and current_stmt.arg2_val is not None and is_concrete(current_stmt.arg2_val):
                self.trace_registers[sink] = [None]*32  # Initialize the register with None
                flag = True  # We can directly use the concrete values
            elif current_stmt.arg1_val is not None and is_concrete(current_stmt.arg1_val):
                for i, v in zip(range(1, 33), values):
                    if current_stmt.arg1_val.value == v:
                        value = self.trace_registers.get(current_stmt.arg2_var, [None]*32)  # Get the original source register
                        self.trace_registers[sink] = [None]*32  # Initialize the register with None
                        for j in range(i):
                            self.trace_registers[sink][31-j] = value[31-j] if j < 32 else None
                        flag = True  # We found a match in the concrete value of arg1_val
                        break
            elif current_stmt.arg2_val is not None and is_concrete(current_stmt.arg2_val):
                for i, v in zip(range(1, 33), values):
                    if current_stmt.arg2_val.value == v:
                        value = self.trace_registers.get(current_stmt.arg1_var, [None]*32)
                        self.trace_registers[sink] = [None]*32  # Initialize the register with None
                        for j in range(i):
                            self.trace_registers[sink][31-j] = value[31-j] if j < 32 else None
                        flag = True  # We found a match in the concrete value of arg2_val
                        break
            
            if not flag:
                for value, source in zip([current_stmt.arg1_val, current_stmt.arg2_val], [current_stmt.arg1_var, current_stmt.arg2_var]):
                    if value is None or not is_concrete(value):
                        original_source = self.trace_registers.get(source, [None]*32)  # Get the original source register
                        if all(x is None for x in original_source):
                            self.trace_registers[sink] = self.trace_registers.get(source, [None]*32)

        elif type_of_stmt in set([TAC_Or, TAC_Xor]):
            sink = current_stmt.res1_var
            for value, source in zip([current_stmt.arg1_val, current_stmt.arg2_val], [current_stmt.arg1_var, current_stmt.arg2_var]):
                if value is None or not is_concrete(value):
                    original_source = self.trace_registers.get(source, [None]*32)  # Get the original source register
                    if all(x is None for x in original_source):
                        self.trace_registers[sink] = self.trace_registers.get(source, [None]*32)
        
        elif type_of_stmt in set([TAC_Not, TAC_Iszero]):
            sink = current_stmt.res1_var
            source = current_stmt.arg1_var
            self.trace_registers[sink] = self.trace_registers.get(source, [None]*32)  # Initialize the register with the value of the source

        elif type_of_stmt == TAC_Byte:
            sink = current_stmt.res1_var
            pos = current_stmt.arg1_val
            if is_concrete(pos):
                if (current_stmt.arg2_val is None or not is_concrete(current_stmt.arg2_val)) and pos < 32:
                    value = self.trace_registers.get(current_stmt.arg2_var, [None]*32)[pos]  # Get the current value in the register
                    self.trace_registers[sink] = [None]*32
                    self.trace_registers[sink][pos] = value
        
        elif type_of_stmt == TAC_Mload:
            offset = state.solver.eval(state.registers[current_stmt.arg1_var])
            sink = current_stmt.res1_var
            self.trace_registers[sink] = [state.globals["memory"].get(offset + i, None) for i in range(32)]  # Load the memory content into the register

        elif type_of_stmt == TAC_Mstore or type_of_stmt == TAC_Mstore8:
            source = current_stmt.arg2_var
            sink = current_stmt.arg1_var
            offset_val = state.solver.eval(state.registers[sink])
            source_var = self.trace_registers.get(source, [None]*32)
            for i in range(32):
                state.globals["memory"][offset_val+i] = source_var[i]

        elif type_of_stmt == TAC_Calldatacopy:
            source = current_stmt.arg2_var
            sink = current_stmt.arg1_var
            dest_offset = state.solver.eval(state.registers[sink])
            source_offset = state.solver.eval(state.registers[source])
            size = state.solver.eval(state.registers[current_stmt.arg3_var])

            for i in range(size):
                state.globals["memory"][dest_offset+i] = CalldataNode(source_offset+i)
    
        elif type_of_stmt == TAC_Callprivate:
            target_bb_id = hex(bv_unsigned_value(current_stmt.arg1_val))
            target_bb = state.project.factory.block(target_bb_id)

            args = current_stmt.arg_vars[1:]
            args_alias = target_bb.function.arguments
        
            alias_arg_map = dict(zip(args_alias, args))
            for sink, source in alias_arg_map.items():
                self.trace_registers[sink] = self.trace_registers.get(source, [None]*32)  # Initialize if not present

        elif type_of_stmt == TAC_Phi:
            most_recent_write_instruction_count = -1
            most_recent_write_register_name = None
            current_stmt_block_id = current_stmt.block_id

            # count the times the current block id appears in the trace
            current_block_count = 0
            in_segment = False
            historical_block_ids = [i.block_id for i in state.trace] + [state.curr_stmt.block_id]
            for block_id in historical_block_ids:
                if block_id == current_stmt_block_id:
                    if not in_segment:
                        current_block_count += 1
                        in_segment = True
                else:
                    in_segment = False

            for arg_var in current_stmt.arg_vars:
                if arg_var not in state.registers:
                    continue

                reg = state.registers.register(arg_var)
                if reg.last_written_instruction_count > most_recent_write_instruction_count and reg.phi_block_id != (current_stmt_block_id, current_block_count):
                    most_recent_write_instruction_count = reg.last_written_instruction_count
                    most_recent_write_register_name = arg_var

            if most_recent_write_register_name is not None:
                sink = current_stmt.res1_var
                source = most_recent_write_register_name
                self.trace_registers[sink] = self.trace_registers.get(source, [None]*32)  # Initialize if not present


        elif type_of_stmt == TAC_Callprivate:
            target_bb_id = hex(bv_unsigned_value(current_stmt.arg1_val))
            target_bb = state.project.factory.block(target_bb_id)

            # read arg-alias map
            args = current_stmt.arg_vars[1:]
            args_alias = target_bb.function.arguments
            alias_arg_map = dict(zip(args_alias, args))
            for sink, source in alias_arg_map.items():
                self.trace_registers[sink] = self.trace_registers.get(source, [None]*32)  # Initialize if not present
    
        elif type_of_stmt == TAC_Returnprivate:
            callprivate_pc, saved_return_pc, callprivate_return_vars = state.callstack.pop()
            state.callstack.append((callprivate_pc, saved_return_pc, callprivate_return_vars))

            returnprivate_args = current_stmt.arg_vars[1:]
            for sink, source in zip(callprivate_return_vars, returnprivate_args):
                self.trace_registers[sink] = self.trace_registers.get(source, [None]*32)  # Initialize if not present


    def setup(self, simgr):
        for state in simgr.states:
            state.globals["memory"] = {}

    
    def check_state(self, simgr, state):
        self.check_data_flow(state)


    def get_register(self, register_name):
        """
        Returns the current state of the registers.
        This can be used to retrieve the current state of the taint analysis.
        """
        return self.trace_registers.get(register_name, [None]*32)
