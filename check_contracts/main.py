import argparse
import logging
import sys
import time
import web3

from utils import *
from check_call import *

LOGGING_FORMAT = "%(levelname)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("skanf - main")


# We need to check if the contract is exploitable.
# If the call is reachable, if the token is controlable, the dst is controlable, the amount is controlable.
if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='Check if a contract is exploitable')
    arg_parser.add_argument('--address', type=str, required=True)
    arg_parser.add_argument('--block', type=str, required=True)
    arg_parser.add_argument('--hash', type=str, required=False)
    arg_parser.add_argument('--mode', type=str, required=False)
    args = arg_parser.parse_args()

    contract_addr = args.address
    contract_addr = web3.Web3.to_checksum_address(contract_addr)
    block_ref = args.block

    if block_ref != "latest":
        if block_ref.isdigit():
            block_ref = int(block_ref)
        else:
            print("Block ref must be a number or latest")
            sys.exit(1)

    # Does the contract exists at the block_ref?
    #   -> If it does not, as we are searching for exploitable bugs, we can skip this.
    # if w3.eth.get_code(contract_addr, block_ref).hex() == '0x':
    #     log.error(f" [!]{contract_addr} selfdestruct at block {block_ref}")
    #     sys.exit(0)

    # Run Gigahorse against it
    target_dir = run_gigahorse(contract_addr, block_ref)
    if target_dir == None:
        log.error(f" [!]{contract_addr} Gigahorse failed")
        sys.exit(0)

    if args.mode is None:
        mode = "concolic" if args.hash is not None else "baseline"
    else:
        mode = args.mode
    
    analyer = Analyzer(target_dir, contract_addr, block_ref, mode)

    start_time = time.time()
    if args.hash is not None:
        calls = get_internal_calls(args.hash, contract_addr)
        calls = sorted(calls, key=lambda x: len(x.calldata))
        print(f" [*] Found {len(calls)} internal calls for {contract_addr} at block {block_ref}")
        
        for call in calls:
            exec_status = execute_call(call)
            if analyer.check_vulnerable_calls_with_historical_transactions(exec_status, call):
                break
    else:
        analyer.check_vulnerable_calls()
    process_time = time.time() - start_time
    analyer.write_process_time(process_time)