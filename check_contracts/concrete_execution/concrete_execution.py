import logging
import networkx as nx

from greed.TAC import TAC_Jump, TAC_Call
from greed.exploration_techniques import DirectedSearch, HeartBeat, Prioritizer
from greed import options
from greed.utils.extra import gen_exec_id
from greed.solver.shortcuts import *
 

from .concrete_call import ConcreteCallStmt
from .parse_historical_transaction import *
from .log_plugin import *
from .execution_plugin import DataflowTracerV2

from ethpwn import *


LOGGING_FORMAT = "%(levelname)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("concrete_execution")
log.setLevel(logging.WARNING)


def execute_call(call):
    block_number = call.block_number
    origin = call.origin
    from_addr = call.from_addr
    to_addr = call.to_addr
    calldata = call.calldata
    value = call.value

    env = get_evm_at_block(block_number)
    plugin = LogPlugin(target_contract=to_addr, new_caller=from_addr, new_origin=origin, overwrite_caller=True, overwrite_origin=True)
    env.register_plugin(plugin)

    txn_data = {
        'to': to_addr,
        'calldata': calldata,
        'value': value
    }
    new_txn = env.build_new_transaction(txn_data)
    rec, status = env.apply(new_txn)

    max_loop = max(plugin.counts.values())
    return status.is_success, plugin.call_pcs, plugin.current_branches, max_loop, plugin.sequences


def concrete_execute(project, contract_addr, call, caller, origin, last_block, calldata):
    print("executing call...")
    p = project

    # options.GREEDY_SHA = True
    # options.LAZY_SOLVES = False
    # options.STATE_INSPECT = False
    # options.MAX_SHA_SIZE = 300
    options.OPTIMISTIC_CALL_RESULTS = True
    # options.DEFAULT_EXTCODESIZE = True
    options.DEFAULT_CREATE2_RESULT_ADDRESS = True
    options.DEFAULT_CREATE_RESULT_ADDRESS = True
    # options.MATH_CONCRETIZE_SYMBOLIC_EXP_EXP = True
    # options.MATH_CONCRETIZE_SYMBOLIC_EXP_BASE = True
    options.SOLVER_TIMEOUT = 120

    if calldata.startswith("0x"):
        calldata = calldata[2:]
    if len(calldata) % 2 != 0:
        calldata_size = len(calldata) // 2 + 1
    else:
        calldata_size = len(calldata) // 2

    
    block_info = w3.eth.get_block(last_block)

    init_ctx = {
        "CALLDATA": calldata,
        "CALLER": caller,
        "ORIGIN": origin,
        "ADDRESS": contract_addr,
        "NUMBER": last_block,
        "DIFFICULTY": block_info["difficulty"],
        "TIMESTAMP": block_info["timestamp"],
        "CALLDATASIZE": calldata_size,
    }

    entry_point = calldata[:8]

    xid = gen_exec_id()
    
    entry_state = p.factory.entry_state(xid=xid, init_ctx=init_ctx,  max_calldatasize=calldata_size, partial_concrete_storage=True)

    simgr = p.factory.simgr(entry_state=entry_state)
    
    # Use multiple techniques to speed up the search
    directed_search = DirectedSearch(call)
    simgr.use_technique(directed_search)
    data_flow_tracer = DataflowTracerV2()
    simgr.use_technique(data_flow_tracer)

    prioritizer = Prioritizer(scoring_function=lambda s: -s.globals['directed_search_distance'])
    simgr.use_technique(prioritizer)
    heartbeat = HeartBeat(beat_interval=1, show_op=False)
    simgr.use_technique(heartbeat)

    log.info(f"  Symbolically executing from {entry_point} to {call.__internal_name__} at {call.id}")

    while True:
        try:
            simgr.run(find=lambda s: type(s.curr_stmt)  == TAC_Call, prune=lambda s: type(s.curr_stmt) == TAC_Jump and len([i for i in s.trace if type(i) == TAC_Jump and (i.arg1_val.value == 0xe000 or i.arg1_val.value == 0xf000)])>=2)
        except Exception as e:
            log.error(f"Error during execution: {e}")
            break
        
        if len(simgr.found) == 1:
            log.info(f"   ✅ Found state for {call.__internal_name__} at {call.id}!")
            state = simgr.one_found

            concrete_call = ConcreteCallStmt(state.curr_stmt, init_ctx)
            prev_calldata = init_ctx["CALLDATA"]  # this is the original calldata
            new_calldata = prev_calldata
            offset_in_calldata = None

            nodes = data_flow_tracer.get_register(state.curr_stmt.arg2_var)
            token_controlable = any(node is not None for node in nodes)
            if token_controlable:
                log.info(f"   ✅ Token is controlable!")
                target_contract = "*"
                sub_nodes = [node for node in nodes if node is not None]
                for node in sub_nodes:
                    new_calldata = new_calldata[:node.pos*2] + "SS" + new_calldata[node.pos*2+2::]
                offset_in_calldata = min([node.pos for node in sub_nodes]) if len(sub_nodes) > 0 else None
            else:
                # If we cannot find a controlable token, we cannot proceed.
                target_contract_raw = state.solver.eval(state.registers[state.curr_stmt.arg2_var], raw=True)
                target_contract = f'0x{bv_unsigned_value(target_contract_raw):040x}'
                log.error(f"   ❌ Token is not controlable! {target_contract}")
            concrete_call.update_target_contract(target_contract, token_controlable, offset_in_calldata)
            
            # handle the function selector
            function_selector_offset = state.solver.eval(state.registers[state.curr_stmt.arg4_var])
            function_selector_nodes = [state.globals["memory"].get(function_selector_offset+i, None) for i in range(4)]
            func_controlable = any(node is not None for node in function_selector_nodes)

            if func_controlable:
                log.info(f"   ✅ Function selector is controlable!")
                target_func = "*"
                sub_nodes = [node for node in function_selector_nodes if node is not None]
                for node in sub_nodes:
                    new_calldata = new_calldata[:node.pos*2] + "SS" + new_calldata[node.pos*2+2::]
                
                offset_in_calldata = min([node.pos for node in sub_nodes]) if len(sub_nodes) > 0 else None
            else:
                size = BVV(4, 256)
                val = state.solver.eval_memory_at(state.memory, BVV(function_selector_offset, 256), size, raw=True)
                target_func =  "0x"+bv_unsigned_value(val).to_bytes(bv_unsigned_value(size), 'big').hex()
                log.error(f"   ❌ Function selector is not controlable! {target_func}")
            
            concrete_call.update_function_selector(target_func, func_controlable, offset_in_calldata)

            # handle the parameters
            for parameter_position in range(3):
                parameter_offset = function_selector_offset + 4 + 32 * parameter_position
                parameter_nodes = [state.globals["memory"].get(parameter_offset+i, None) for i in range(32)]
                parameter_controlable = any(node is not None for node in parameter_nodes)
                
                if parameter_controlable:
                    log.info(f"   ✅ Parameter {parameter_position} is controlable!")
                    parameter_value = "*"
                    sub_nodes = [node for node in parameter_nodes if node is not None]
                    for node in sub_nodes:
                        new_calldata = new_calldata[:node.pos*2] + "SS" + new_calldata[node.pos*2+2::]

                    offset_in_calldata = min([node.pos for node in sub_nodes]) if len(sub_nodes) > 0 else None
                else:
                    size = BVV(32, 256)
                    val = state.solver.eval_memory_at(state.memory, BVV(parameter_offset, 256), size, raw=True)
                    parameter_value = bv_unsigned_value(val).to_bytes(bv_unsigned_value(size), 'big').hex()
                    log.error(f"   ❌ Parameter {parameter_position} is not controlable! Using value {parameter_value}")
                    
                concrete_call.update_parameter(parameter_position, parameter_value, parameter_controlable, offset_in_calldata)
            
            new_calldata = new_calldata[:calldata_size*2]
            concrete_call.set_calldata(init_ctx["CALLDATA"], new_calldata, calldata_size)
            concrete_call.log_traces([i.id for i in state.trace])
            concrete_call.check_sensitivity()
            print("Final calldata:", prev_calldata)
            return concrete_call
        else:
            print(f"   ❌ Found {len(simgr.found)} states, retrying...")
            log.error(f"   ❌ Could not find state for {call.__internal_name__} at {call.id}!")
            break
    return None
