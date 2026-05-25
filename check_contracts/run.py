import argparse
import json
import logging
import os
import sys
import web3


from greed import Project
import web3.tools

from constants import *
from utils import *
from inspect_call import inspect_call

from path_feasibility import check_call_reachability


LOGGING_FORMAT = "%(levelname)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("check_contracts")
log.setLevel(logging.INFO)


def check_vulnerable_calls(target_dir):
    # Let's create the greed project
    try:
        project = Project(target_dir=target_dir)
    except Exception as e:
        print(f'Could not create greed project for {contract_addr}')
        sys.exit(0)

    # Let's find all the CALLs in the contract
    calls = list()
    callcodes = list()
    for func in project.function_at.values():
        # find all the CALLs (CALLCODEs) in the contract
        calls.extend([s for block in func.blocks for s in block._statement_at.values() if s.__internal_name__ == "CALL"])
        callcodes.extend([s for block in func.blocks for s in block._statement_at.values() if s.__internal_name__ == "CALLCODE"])

    if len(calls) + len(callcodes) == 0:
        print("No CALL(s) have been found in the contract. Aborting.")
        with open(os.path.join(target_dir, "output.json"), "w") as f:
            json.dump({"verified": [], "unverified": []}, f, indent=4)
        sys.exit(0)

    possible_origin_addresses = [TEST_SENDER] + load_possible_origin_addresses(target_dir) #+ ['0xdaf886a8ccf0af82088efbe7bea4273174f86500']
    call_reports = list()
    # check all the calls
    for func in project.function_at.values():
        # find all CALLs in the function
        calls = [s for block in func.blocks for s in block._statement_at.values() if s.__internal_name__ == "CALL"]
        # print([s.id for s in calls])

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
                inspect_call(project, target_dir, contract_addr, caller, origin, call, block_ref, call_report)
                print(f'Call {call.id}, function: {func.id}', call_report['calldata'])

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
                        log.info(f'Call {call.id} is reachable: {call_report["verified"]}')
                        call_report['call_tac_id'] = call.id
                
                if call_report.get('verified', False) == True:
                    break
            call_reports.append(call_report)
            if len([i for i in call_reports if i.get('verified', True) == True]) >= 1:
                break

    for call_report in call_reports:
        if call_report['sensitive'] and call_report['verified'] == True:
            print(f'{bcolors.OKGREEN}{call_report}{bcolors.ENDC}')
        elif call_report['sensitive'] and call_report['verified'] == False:
            print(f'{bcolors.FAIL}{call_report}{bcolors.FAIL}')
        else:
            print(call_report)

    output = dict()
    output['verified'] = [call_report for call_report in call_reports if call_report['sensitive'] and call_report['verified'] == True]
    output['unverified'] = [call_report for call_report in call_reports if call_report['sensitive'] and call_report['verified'] == False]
    with open(os.path.join(target_dir, "output.json"), "w") as f:
        json.dump(output, f, indent=4)
    print(f"result: {len(output['verified'])} verified, {len(output['unverified'])} unverified")


# We need to check if the contract is exploitable.
# If the call is reachable, if the token is controlable, the dst is controlable, the amount is controlable.
if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='Check if a contract is exploitable')
    arg_parser.add_argument('--address', type=str, required=True)
    arg_parser.add_argument('--block', type=int, required=True)
    args = arg_parser.parse_args()

    contract_addr = args.address
    contract_addr = web3.Web3.to_checksum_address(contract_addr)
    block_ref = args.block

    # Does the contract exists at the block_ref?
    #   -> If it does not, as we are searching for exploitable bugs, we can skip this.
    if w3.eth.get_code(contract_addr, block_ref).hex() == '0x':
        log.info(f" [!]{contract_addr} selfdestruct at block {block_ref}")
        sys.exit(0)

    # Run Gigahorse against it
    target_dir = run_gigahorse(contract_addr, hex(block_ref))
    if target_dir == None:
        log.info(f" [!]{contract_addr} Gigahorse failed")
        sys.exit(0)

    check_vulnerable_calls(target_dir)
