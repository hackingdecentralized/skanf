
import logging
import datetime 
import networkx as nx
import re

from greed.TAC import TAC_Statement, TAC_Jump, TAC_Calldataload
from greed.exploration_techniques import DirectedSearch, HeartBeat, Prioritizer
from greed.exploration_techniques.other import LoopLimiter
from greed import Project
from greed import options
from greed.utils.extra import gen_exec_id
from greed.solver.shortcuts import *
 
from constants import *
from taint_analysis import CalldataToCallTarget
from concrete_execution import PathLimiter
from utils import *


logger = logging.getLogger("greed.exploration_techniques.heartbeat")
logger.setLevel(logging.CRITICAL + 1)

LOGGING_FORMAT = "%(levelname)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("analyze_call")


# Class to store information regarding a call
class CallInfo():
    def __init__(self, call_stmt):

        self._wrapped_call = call_stmt

        self.has_static_target_contract = None
        self.has_static_target_function  = None

        self.target_contract_classification = 'x'
        self.target_contract_classification_type = ''
        self.target_function_classification = 'y'
        self.target_function_classification_type = ''

        # If static, here we have the values
        self.contract_target = None
        self.function_target = None

    def __getattr__(self, attr):
        if attr in self.__dict__:
            return getattr(self,attr)
        return getattr(self._wrapped_call, attr)


# N stands for "Not controllable", S stands for "Static"
def analyze_call_from_ep(project, worker_folder, contract_addr, caller, origin, function_selector, call, calldata, last_block, taint_analysis_for_contract, taint_analysis_for_func, first_solution_for_contract_target, first_solution_for_function_target, traces=None):
    
    p = project

    options.GREEDY_SHA = True
    options.LAZY_SOLVES = False
    options.STATE_INSPECT = False
    options.MAX_SHA_SIZE = 300
    options.OPTIMISTIC_CALL_RESULTS = True
    options.DEFAULT_EXTCODESIZE = True
    options.DEFAULT_CREATE2_RESULT_ADDRESS = True
    options.DEFAULT_CREATE_RESULT_ADDRESS = True
    options.MATH_CONCRETIZE_SYMBOLIC_EXP_EXP = True
    options.MATH_CONCRETIZE_SYMBOLIC_EXP_BASE = True
    options.SOLVER_TIMEOUT = 120

    if type(calldata) == int:
        calldata_size = calldata
        ctx_calldata = function_selector if function_selector is not None else "0x"
    else:
        calldata_size = len(calldata) // 2 if calldata is not None else 0
        ctx_calldata = calldata if calldata is not None else "0x"

    MAX_CALLDATA_SIZE = calldata_size if calldata_size != 0 else 1024
    
    block_info = w3.eth.get_block(last_block)

    init_ctx = {
        "CALLDATA": ctx_calldata,
        "CALLER": caller,
        "ORIGIN": origin,
        "ADDRESS": contract_addr,
        "NUMBER": last_block,
        "DIFFICULTY": block_info["difficulty"],
        "TIMESTAMP": block_info["timestamp"],
        "CALLDATASIZE": MAX_CALLDATA_SIZE,
    }

    xid = gen_exec_id()
    
    entry_state = p.factory.entry_state(xid=xid, init_ctx=init_ctx,  max_calldatasize=MAX_CALLDATA_SIZE, partial_concrete_storage=True)

    simgr = p.factory.simgr(entry_state=entry_state)
    
    # Use multiple techniques to speed up the search
    directed_search = DirectedSearch(call)
    simgr.use_technique(directed_search)

    prioritizer = Prioritizer(scoring_function=lambda s: -s.globals['directed_search_distance'])
    simgr.use_technique(prioritizer)
    heartbeat = HeartBeat(beat_interval=1, show_op=False)
    simgr.use_technique(heartbeat)

    log.info(f"  Symbolically executing from {function_selector} to {call.__internal_name__} at {call.id}")
    
    result = dict()

    while True:
        try:
            simgr.run(find=lambda s: s.curr_stmt.id  == call.id, prune=lambda s: type(s.curr_stmt) == TAC_Jump and len([i for i in s.trace if type(i) == TAC_Jump and i.arg1_val is not None and i.arg1_val.value == 0xe000])>=2)
            # simgr.run(find=lambda s: s.curr_stmt.id == '0x10000')#, prune=lambda s: type(s.curr_stmt) == TAC_Jump and len([i for i in s.trace if type(i) == TAC_Jump and i.arg1_val.value == 0xf000])>=2)
        except Exception as e:
            result['ep'] = function_selector
            result['status'] = "SYMEXCEPTION-{}".format(e)
            return result
        
        if len(simgr.found) == 1:
            log.info(f"   ✅ Found state for {call.__internal_name__} at {call.id}!")
            state = simgr.one_found

            # limit the index of the calldata to the calldatasize
            data = []
            for trace in state.trace:
                if type(trace) == TAC_Calldataload:
                    data.append(trace)  

            pattern = r"READN_CALLDATA_(\d+)_BASE(\d+)_(\d+)_(\d+)"
            for i in data:
                var = state.registers[i.arg1_var]
                smt2 = var.dump_smt2()
                matches = re.findall(pattern, smt2)
                if matches:
                    state.add_constraint(BV_UGE(state.calldatasize, var))

            if state.solver.frame != 0:
                panic(worker_folder, msg="Wrong frame for solver when raching CALL (!=0)")

            if not state.solver.is_sat():
                log.error(f"❌ Found state is UNSAT :(")
                simgr.found.pop()
                continue
            
            log.info(f"   Running taint analysis now...")
            ta = CalldataToCallTarget(state, worker_folder, taint_analysis_for_contract, taint_analysis_for_func, first_solution_for_contract_target,  first_solution_for_function_target)
            try:
                ta.run()
            except Exception as e:
                result['ep'] = function_selector
                result['status'] = "TAINT-EXCEPTION (UNREACHABLE)"
                return result


            result['status'] = "SUCCESS"
            result['ep'] = function_selector
            result['calldata'] = ta.calldata_for_call

            result['calldata_size'] = ta.calldata_size
            if taint_analysis_for_contract:
                result["target_contract_tainted"] =  "A"  if ta.target_contract_tainted else "N"
                if result["target_contract_tainted"] == "N":
                    result["solution_target_contract"] = ta.first_solution_for_contract_target
                    log.info(f"  {call.id} target contract: {result['solution_target_contract']}")
            if taint_analysis_for_func:
                result["target_function_tainted"] =  "A"  if ta.target_function_tainted else "N" 
                if result["target_function_tainted"] == "N":
                    result["solution_target_function"] = ta.first_solution_for_function_target
                    log.info(f"  {call.id} target function: {result['solution_target_function']}")
            
            if ta.target_destination_tainted:
                result["destination"] = "*"
                result["destination_offset"] = ta.destination_offset
            else:
                result["destination"] = ta.first_solution_for_destination
            
            if ta.target_amount_tainted:
                result["amount"] = "*"
                result["amount_offset"] = ta.amount_offset
            else:
                result["amount"] = ta.first_solution_for_amount

            return result
        else:
            result['ep'] = function_selector
            result['status'] = "UNREACHABLE"
            return result


# Here we want to understand from which function it is possible to reach this specific CALL statement. 
# Returns a list of entry-points that can reach the CALL.
def how_to_reach(p: Project, target_call:TAC_Statement):
    target_function = p.factory.block(target_call.block_id).function

    # If the function containing the CALL is public we are done.
    if target_function.public:
        return [target_function]

    # Otherwise, we need to find the entry points that lead to this CALL using the callgraph.
    # To do that, we start from all the public functions, and see if they can reach the function.id of the CALL under analysis.
    # For obfuscated contracts, we need to consider that it only includes one function (identified by Gigahorse).
    if len(p.function_at.values()) > 1:
        possible_entry_points = [f for f in p.function_at.values() if f.public and f.id != '0x0']
    else:
        possible_entry_points = [f for f in p.function_at.values()]
    entry_points = set()
    for ep in possible_entry_points:
        if nx.has_path(p.callgraph, source=ep, target=target_function):
            entry_points.add(ep)
    
    if len(entry_points) == 0:
        # add 0x0 as a fallback entry point
        entry_points.add(p.function_at['0x0'])
    
    return entry_points


def inspect_dynamically(worker_folder, p, contract_addr, caller, origin, call, calldata, last_block, taint_analysis_for_contract, taint_analysis_for_func, first_solution_for_contract_target,  first_solution_for_function_target, traces, function_selector):
    if traces is not None:
        return analyze_call_from_ep(p, worker_folder, contract_addr, caller, origin, function_selector, call, calldata, last_block, taint_analysis_for_contract, taint_analysis_for_func, first_solution_for_contract_target,  first_solution_for_function_target, traces)
    else:
        entry_points = how_to_reach(p, call)
        for ep in entry_points:
            if ep.signature != None or ep.id == '0x0':
                result = analyze_call_from_ep(p, worker_folder, contract_addr, caller, origin, ep.signature, call, calldata, last_block, taint_analysis_for_contract, taint_analysis_for_func, first_solution_for_contract_target,  first_solution_for_function_target, None)
                return result
    return {'ep': "", 'status': "NO_ENTRY_POINT"}


def inspect_static(call):
    # Do we have a static value for the register holding the contract address?
    # Check if the contract address is static
    if call.arg2_val:
        #log.info(f"  {call.__internal_name__} at {call.id} calls contract at {hex(call.arg2_val.value)}")
        call.has_static_target_contract = True
        call.target_contract_classification = "N" # Not controllable
        call.target_contract_classification_type = "S" # Static classification (Gigahorse)
        call.static_target_contract = hex(call.arg2_val.value)
    # Check if the function signature is static
    if call.likely_known_target:
        #log.info(f"  {call.__internal_name__} at {call.id} calls function {call.target_function}")
        call.has_static_target_function = True
        call.target_function_classification = "N"
        call.target_function_classification_type = "S"
        call.static_target_function = call.likely_known_target


def inspect_call(project, worker_folder, contract_addr, caller, origin, call, calldata, last_block, call_report, traces=None, function_selector=None):
    p = project

    # Wrap the call object to add metadata regarding this analysis
    call = CallInfo(call)

    job_start_time = datetime.datetime.now().timestamp()
    log.info(f" Statically investigating {call.__internal_name__} at {call.id} from {origin}")

    inspect_static(call)

    # Case 1: NN_CALL, we are done, no need for further analysis (both target contract and function are not controllable).
    if call.target_contract_classification  == "N" and call.target_function_classification == "N":
        log.info(f"  {call.id} is a NN_CALL (SS)")
        call_report['entry_point'] = '-'
        call_report['classification'] = "NN"
        call_report['classification_type'] = "SS"
        call_report['contract_target'] = call.static_target_contract
        call_report['function_sig_target'] = call.static_target_function
        call_report['result'] = "SUCCESS"
        call_report['calldata'] = "0x"
        call_report['calldata_size'] = 0
        call_report['analysis_time'] = datetime.datetime.now().timestamp() - job_start_time

        call_report["sensitive"] = call_report['function_sig_target'] in SENSITIVE_SIGNATURES and call_report['contract_target'] in SENSITIVE_ADDRESSES
        # if the call is sensitive, we need to check if the dst and amount are controlable.
        if call_report["sensitive"]:
            result = inspect_dynamically(worker_folder, p, contract_addr, caller, origin, call, calldata, last_block, taint_analysis_for_contract=False, taint_analysis_for_func=False, first_solution_for_contract_target=call.static_target_contract, first_solution_for_function_target=call.static_target_function, traces=traces, function_selector=function_selector)
            if result['status'] == "SUCCESS":
                call_report['entry_point'] = result["ep"]
                call_report['classification'] = "NN"
                call_report['result'] = "SUCCESS"
                call_report['calldata'] = result["calldata"]
                call_report['calldata_size'] = result["calldata_size"]
                call_report["destination"] = result["destination"]
                call_report["amount"] = result["amount"]
                call_report['destination_offset'] = result.get("destination_offset", -1)
                call_report['amount_offset'] = result.get("amount_offset", -1)
                
                call_report['analysis_time'] = datetime.datetime.now().timestamp() - job_start_time
                log.info(f"  {call.id} is a NN_CALL (SS)")
            else:
                call_report['entry_point'] = result["ep"]
                call_report['result'] = result["status"]
                call_report['analysis_time'] = datetime.datetime.now().timestamp() - job_start_time
                log.info(f"  {call.id} is a NN_CALL (SS) - {result['status']}")

    # Case 2: Ny_CALL, contract is constant, function is unknown, run our dynamic analysis
    elif call.target_contract_classification  == "N" and call.target_function_classification == "y":
        log.info(f"  {call.id} is a Ny_CALL")
        
        call_report['classification'] = "Ny"
        call_report['classification_type'] = "SD"
        call_report['contract_target'] = call.static_target_contract
        call_report['function_sig_target'] = "-"
        call_report['calldata'] = '0x'
        call_report['calldata_size'] = 0

        result = inspect_dynamically(worker_folder, p, contract_addr, caller, origin, call, calldata, last_block, taint_analysis_for_contract=False, taint_analysis_for_func=True, first_solution_for_contract_target=call.static_target_contract, first_solution_for_function_target=None, traces=traces, function_selector=function_selector)  

        if result['status'] == "SUCCESS":
            call_report['entry_point'] = result["ep"]
            call_report['classification'] = "N" + result["target_function_tainted"]
            
            if result["target_function_tainted"] == "N":
                call_report['function_sig_target'] = result["solution_target_function"]
            else:
                call_report['function_sig_target'] = "*"
            call_report['result'] = "SUCCESS"
            call_report['calldata'] = result["calldata"]
            call_report['calldata_size'] = result["calldata_size"]
            call_report['destination'] = result["destination"]
            call_report['amount'] = result["amount"]
            call_report['destination_offset'] = result.get("destination_offset", -1)
            call_report['amount_offset'] = result.get("amount_offset", -1)
            call_report['analysis_time'] = datetime.datetime.now().timestamp() - job_start_time
            log.info(f"  {call.id} is a {call_report['classification']}_CALL (SD)")
        else:
            call_report['entry_point'] = result["ep"]
            call_report['result'] = result["status"]
            call_report['analysis_time'] = datetime.datetime.now().timestamp() - job_start_time
            log.info(f"  {call.id} is a {call_report['classification']}_CALL (SD) - {result['status']}")


    # Case 3: xy_CALL:
    # nothing can be said statically about anything, proceed with full taint analysis.
    elif call.target_contract_classification  == "x" and call.target_function_classification == "y":
        log.info(f"  {call.id} is a xy_CALL")

        call_report['classification'] = "xy"
        call_report['classification_type'] = "DD"
        call_report['contract_target'] = "-"
        call_report['function_sig_target'] = "-"
        call_report['calldata'] = '0x'
        call_report['calldata_size'] = 0

        result = inspect_dynamically(worker_folder, p, contract_addr, caller, origin, call, calldata, last_block, taint_analysis_for_contract=True, taint_analysis_for_func=True, first_solution_for_contract_target=None, first_solution_for_function_target=None, traces=traces, function_selector=function_selector)

        if result['status'] == "SUCCESS":
            call_report['entry_point'] = result["ep"]
            call_report['classification'] = result["target_contract_tainted"] + result["target_function_tainted"]
            call_report['classification_type'] = "DD"
            if result["target_contract_tainted"] == "N":
                call_report['contract_target'] = result["solution_target_contract"]
            else:
                call_report['contract_target'] = "*"
            if result["target_function_tainted"] == "N":
                call_report['function_sig_target'] = result["solution_target_function"]
            else:
                call_report['function_sig_target'] = "*"
            call_report['result'] = "SUCCESS"
            call_report['calldata'] = result["calldata"]
            call_report['calldata_size'] = result["calldata_size"]
            call_report['destination'] = result["destination"]
            call_report['amount'] = result["amount"]
            call_report['destination_offset'] = result.get("destination_offset", -1)
            call_report['amount_offset'] = result.get("amount_offset", -1)
            call_report['analysis_time'] = datetime.datetime.now().timestamp() - job_start_time
            log.info(f"  {call.id} is a {call_report['classification']}_CALL (DD)")
        else:
            call_report['entry_point'] = result["ep"]
            call_report['result'] = result["status"]
            call_report['analysis_time'] = datetime.datetime.now().timestamp() - job_start_time
            log.info(f"  {call.id} is a {call_report['classification']}_CALL (SD) - {result['status']}")


    # Case 4: xN_CALL:
    # nothing can be said statically about targetContract, targetFunction is not controllable.
    elif call.target_contract_classification  == "x" and call.target_function_classification == "N":
        log.info(f"  {call.id} is a xN_CALL")

        call_report['classification'] = "xN"
        call_report['classification_type'] = "DS"
        call_report['contract_target'] = "-"
        call_report['calldata'] = '0x'
        call_report['calldata_size'] = 0
        call_report['function_sig_target'] = call.static_target_function

        result = inspect_dynamically(worker_folder, p, contract_addr, caller, origin, call, calldata, last_block, taint_analysis_for_contract=True, taint_analysis_for_func=False, first_solution_for_contract_target=None, first_solution_for_function_target=call.static_target_function, traces=traces, function_selector=function_selector)

        if result['status'] == "SUCCESS":
            call_report['entry_point'] = result["ep"]
            call_report['classification'] = result["target_contract_tainted"] + "N"
            call_report['classification_type'] = "DS"
            if result["target_contract_tainted"] == "N":
                call_report['contract_target'] = result["solution_target_contract"]
            else:
                call_report['contract_target'] = "*"
            
            call_report['result'] = "SUCCESS"
            call_report['calldata'] = result["calldata"]
            call_report['calldata_size'] = result["calldata_size"]
            call_report['destination'] = result["destination"]
            call_report['amount'] = result["amount"]
            call_report['destination_offset'] = result.get("destination_offset", -1)
            call_report['amount_offset'] = result.get("amount_offset", -1)
            call_report['analysis_time'] = datetime.datetime.now().timestamp() - job_start_time
            log.info(f"  {call.id} is a {call_report['classification']}_CALL (DS)")
        else:
            call_report['entry_point'] = result["ep"]
            call_report['result'] = result["status"]
            call_report['analysis_time'] = datetime.datetime.now().timestamp() - job_start_time
            log.info(f"  {call.id} is a {call_report['classification']}_CALL (SD) - {result['status']}")

    else:
        panic(worker_folder, msg="Unexpected classification")

    # Check if the call is sensitive
    if call_report['classification'] == "AA":
        call_report['sensitive'] = True
    elif call_report["classification"] == "NN":
        call_report['sensitive'] = call_report['function_sig_target'] in SENSITIVE_SIGNATURES and call_report['contract_target'] in SENSITIVE_ADDRESSES
    elif call_report["classification"][0] == "N":
        call_report['sensitive'] = call_report['contract_target'] in SENSITIVE_ADDRESSES
    elif call_report["classification"][1] == "N":
        call_report['sensitive'] = call_report['function_sig_target'] in SENSITIVE_SIGNATURES
    else:
        call_report['sensitive'] = False
    
