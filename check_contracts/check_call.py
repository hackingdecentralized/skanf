import logging
import os
import time

from greed import Project

# from our own code
from constants import *
from utils import *
from inspect_call import inspect_call

from concrete_execution import concrete_execute
from path_feasibility import check_call_reachability


LOGGING_FORMAT = "%(levelname)s | %(message)s"
logging.basicConfig(level=logging.WARNING, format=LOGGING_FORMAT)
log = logging.getLogger("check_contract_calls")



def check_dest(dest, caller):
    if caller == '' or dest == '':
        return False
    if dest == "*":
        return True
    return int(dest, 16) == int(caller, 16)


def check_and_output(call_reports, output_path, print_log=True):
    # print the call reports
    if print_log:
        for call_report in call_reports:
            if call_report['sensitive'] and call_report['verified'] == True and check_dest(call_report.get('destination', '0x0'), call_report['caller']):
                print(f'{bcolors.OKGREEN}{call_report}{bcolors.ENDC}')
            elif call_report['sensitive'] and (call_report['verified'] == False or check_dest(call_report.get('destination', '0x0'), call_report['caller'])):
                print(f'{bcolors.FAIL}{call_report}{bcolors.FAIL}')
            else:
                print(call_report)

    output = {
        'verified': [],
        'unverified': []
    }
    for call_report in call_reports:
        if call_report["sensitive"]:
            if call_report.get('verified', False) == True and check_dest(call_report.get('destination', '0x0'), call_report['caller']):
                output['verified'].append(call_report)
            else:
                output['unverified'].append(call_report)                    
    
    dump_output(output_path, output)
    
    log.info(f"result: {len(output['verified'])} verified, {len(output['unverified'])} unverified")
    print(f"Output saved to {output_path}")
    return len(output['verified']) > 0


class Analyzer:
    def __init__(self, target_dir, contract_addr, block_ref, mode='baseline'):
        self.target_dir = target_dir
        self.contract_addr = contract_addr
        self.block_ref = block_ref
        self.mode = mode


    def pre_check_calls(self):
        target_dir = self.target_dir
        # Let's create the greed project
        try:
            project = Project(target_dir=target_dir)
    
        except Exception as e:
            log.error(f'Could not create greed project for {target_dir}')
            return None

        # Let's find all the CALLs in the contract
        calls = list()
        callcodes = list()
        for func in project.function_at.values():
            # find all the CALLs (CALLCODEs) in the contract
            calls.extend([s for block in func.blocks for s in block._statement_at.values() if s.__internal_name__ == "CALL"])
            callcodes.extend([s for block in func.blocks for s in block._statement_at.values() if s.__internal_name__ == "CALLCODE"])
        calls.extend([s for s in project.statement_at.values() if s.__internal_name__ == "CALL"])

        log.info(f"Found {len(calls)} CALLs and {len(callcodes)} CALLCODEs in the contract.")
        total_call_counts = len(calls) + len(callcodes)
        if total_call_counts == 0:
            log.error("No CALL(s) have been found in the contract. Aborting.")
            return None
        
        project._w3 = w3
        
        return project


    def check_vulnerable_calls(self):
        target_dir = self.target_dir
        contract_addr = self.contract_addr
        block_ref = self.block_ref

        run_gigahorse(contract_addr, block_ref)
        
        output_path = os.path.join(target_dir, f"output_{self.mode}.json")
        project = self.pre_check_calls()

        # if we cannot create the project, we cannot proceed. return empty output.
        if project is None:
            output = {"verified": [], "unverified": []}
            dump_output(output_path, output)
            return

        possible_origin_addresses = [TEST_SENDER] + load_possible_origin_addresses(target_dir)
        call_reports = list()
        stop_flag = False
        # check all the calls
        for func in project.function_at.values():
            # find all CALLs in the function
            calls = [s for block in func.blocks for s in block._statement_at.values() if s.__internal_name__ == "CALL"]

            if len(calls) == 0:
                # print(f"No CALL(s) have been found in the function {func.id}.")
                continue

            for num, call in enumerate(calls):
                # every call has a unique id in the contract.
                caller = TEST_SENDER
                call_report = {"caller": caller}
                # We test all possible origins
                for index, origin in enumerate(possible_origin_addresses):
                    call_report["origin"] = origin
                    inspect_call(project, target_dir, contract_addr, caller, origin, call, 1024, block_ref, call_report)

                    if call_report['sensitive']:
                        log.info(f'Checking reachability for {call.id}')
                        # print(call_report)
                        if check_call_reachability(contract_addr, caller, origin, block_ref, call_report['calldata'], call.id):
                            call_report['verified'] = True
                            log.info(f'Call {call.id} is reachable: {call_report["verified"]}')
                            call_report['call_tac_id'] = call.id
                            break
                        else:
                            call_report['verified'] = False
                            log.info(f'Call {call.id} is not reachable: {call_report["verified"]}')
                            call_report['call_tac_id'] = call.id
                    
                    if call_report.get('verified', False) == True:
                        break

                call_reports.append(call_report)
                # we can return if we can a call satisfying the following conditions.
                # 1. it is sensitive
                # 2. it is verified
                # 3. the destination is the same as the caller or we can control the destination.
                if len([i for i in call_reports if i.get('verified', False) == True and i.get('sensitive', False) == True and check_dest(i.get('destination', '0x0'), caller)] ) >= 1:
                    log.info(f'{bcolors.OKGREEN}Found a reachable call {call_report}{bcolors.ENDC}')
                    stop_flag = True
                    break

            if stop_flag:
                break

        return check_and_output(call_reports, output_path, print_log=True)
    

    def check_vulnerable_calls_with_historical_transactions(self, exec_status, callinfo):
        target_dir = self.target_dir
        project = self.pre_check_calls()
        output_path = os.path.join(target_dir, f"output_{self.mode}.json")

        is_success, call_pcs, branches, max_loop, sequences = exec_status
        call_ids = set([call_pc[0] for call_pc in call_pcs])
        call_with_branches = [set([call_pc[0],*call_pc[1]]) for call_pc in call_pcs]

        calls = [s for s in project.statement_at.values() if s.__internal_name__ == "CALL"]
        new_calls = []
        for call in calls:
            if call.id in call_ids:
                new_calls.append(call)
            else:
                if call.id.count('0x') == 2:
                    pcs = set([f'0x{i}' for i in call.id.split('0x')])
                    if any(len(item & pcs)==2 for item in call_with_branches):
                        new_calls.append(call)
        calls = new_calls
        if len(calls) > 0:
            print(f"Filtered calls: {[call.id for call in calls]}")

        if len(calls) == 0:
            print(f"No CALL(s) have been found in the contract. Aborting.")
            return False
        
        call_reports = []
        for call in calls:
            caller = TEST_SENDER
            origins = [TEST_SENDER, callinfo.origin]
            for origin in origins:
                start_time = time.time()
                concrete_call = concrete_execute(project, callinfo.to_addr, call, caller, origin, callinfo.block_number, callinfo.calldata)
                if concrete_call is None:
                    log.warning(f"Could not execute call {call.id}. Skipping.")
                    continue
                call_report = concrete_call.dump()

                if check_call_reachability(self.contract_addr, caller, origin, self.block_ref, call_report['original_calldata'], call.id):
                    call_report['verified'] = True
                    log.info(f'Call {call.id} is reachable')
                else:
                    call_report['verified'] = False
                    log.info(f'Call {call.id} is not reachable')

                call_report["analysis_time"] = time.time() - start_time
                call_reports.append(call_report)

                if len([i for i in call_reports if i.get('verified', False) == True and i.get('sensitive', False) == True and check_dest(i.get('destination', '0x0'), caller)] ) >= 1:
                    log.info(f'{bcolors.OKGREEN}Found a reachable call {call_report}{bcolors.ENDC}')
                    break
                # break

        output = dict()
        output['verified'] = [call_report for call_report in call_reports if call_report['sensitive'] and call_report['verified'] == True]
        output['unverified'] = [call_report for call_report in call_reports if call_report['sensitive'] and call_report['verified'] == False]
        return check_and_output(call_reports, output_path, print_log=True)


    def get_output_path(self):
        return os.path.join(self.target_dir, f"output_{self.mode}.json")
    

    def write_process_time(self, process_time):
        output_path = self.get_output_path()
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                data = json.load(f)
                data["process_time"] = process_time
        else:
            data = {"process_time": process_time}
        
        with open(output_path, "w") as f:
            json.dump(data, f, indent=4)
