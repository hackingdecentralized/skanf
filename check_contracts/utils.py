import json
import logging
import os
import subprocess
import sys

from greed import Project
from web3 import Web3
from web3.middleware import geth_poa_middleware

from constants import *

_WEB3_PROVIDER = os.environ.get('WEB3_PROVIDER') or 'http://127.0.0.1:8545'
w3 = Web3(Web3.HTTPProvider(_WEB3_PROVIDER))

if os.environ.get('NETWORK', "ETH") != "ETH":
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)

if not w3.is_connected():
    raise RuntimeError(
        f"Could not connect to RPC at {_WEB3_PROVIDER}. "
        "Set WEB3_PROVIDER to a reachable Ethereum JSON-RPC endpoint "
        "(e.g. export WEB3_PROVIDER=https://mainnet.infura.io/v3/<KEY>)."
    )


# Set up logging
log = logging.getLogger("check_contract_utils")


# We panic only when there are errors that 
# need to be fixed in the worker/analyses
def panic(worker_folder, msg=''):
    log.critical(f"[!!] {msg}")
    # Create panic file to signal the worker to stop.
    with open(worker_folder + "/.panic", "w") as f:
        f.write("panic")


# parsing contract hex
def is_contract(w3, contract_addr):
    if w3.eth.get_code(contract_addr).hex() != "0x":
        return True
    else:
        return False


def get_contract(address, where, when="latest"):
    if is_contract(w3, address):
        data = w3.eth.get_code(address, when).hex()
        full_path = os.path.join(where,"contract.hex")
        log.info(f'Saving contract at {full_path}')
        with open(full_path, "w") as f:
            f.write(data)
    else:
        log.info(f"{address} is not a contract")
        sys.exit(1)

# Create the experiment folder for the contract.
def get_exp_folder(contract_addr):
    contract_addr = Web3.to_checksum_address(contract_addr)
    exp_folder = os.path.join(WORKDIR, contract_addr[0:5], contract_addr)

    if not os.path.exists(exp_folder):
        os.makedirs(exp_folder)

    return exp_folder


# return True if any of the indirect jump files exist and have content.
def check_jump_table(exp_folder):
    target_files = ["JTA_JUMP_To_CallValue.csv", "JTA_JUMP_To_Calldata.csv", "JTA_JUMP_To_MLOAD.csv", "JTA_JUMP_To_SLOAD.csv"]
    for target_file in target_files:
        with open(os.path.join(exp_folder, target_file), "r") as f:
            lines = f.readlines()
            if len(lines) > 0:
                return True
    return False


# Gigahorse invocation over a target address.
def run_gigahorse(contract_addr, block_ref):
    # Create folder if it does not exist
    exp_folder = get_exp_folder(contract_addr)
    # exp_folder = os.path.join(WORKDIR, contract_addr[0:5], contract_addr)
    try:
        Project(target_dir=exp_folder)
        return exp_folder
    except Exception as e:
        pass

    # Print exp folder
    log.info(f"Exp folder: {exp_folder}")

    # Get the contract bytecode from the chain
    get_contract(contract_addr, exp_folder, block_ref)

    # Check if contract.hex exists
    folder = os.path.join(exp_folder, "contract.hex")
    if not os.path.exists(folder):
        log.error(f"Contract.hex does not exist at {folder}")

    # Run Gigahorse on the contract.hex file
    log.info(f"Running Gigahorse on {contract_addr}")

    command = f"cd {exp_folder} && timeout {GIGAHORSE_TIMEOUT} {GIGAHORSE_ANALYSIS_SCRIPT} --file ./contract.hex"
    log.info(f"Executing {command}")
    subprocess.run(command, shell=True, check=True)

    if check_jump_table(exp_folder):
        fix_jump_table_command = f"cd {exp_folder} && timeout {GIGAHORSE_TIMEOUT} {GIGAHORSE_ANALYSIS_SCRIPT} --file ./contract.hex --fix"
        log.warning("Jump table detected. Fixing it...")
        log.warning(f"Executing {fix_jump_table_command}")
        subprocess.run(fix_jump_table_command, shell=True, check=True)

    # Check if .tac exists
    if not os.path.exists(os.path.join(exp_folder, "contract.tac")):
        # Report this in the gigahorse fails file
        with open(GIGAHORSE_FAILS, "a") as gigahorse_fails:
            log.error("Gigahorse analysis failed on {contract_addr}")
            gigahorse_fails.write(f"{contract_addr}\n")
            return None

    log.info("Gigahorse finished!")

    return exp_folder


def load_possible_origin_addresses(exp_folder):
    with open(os.path.join(exp_folder, "StaticallyOriginGuardedBlock.csv"), "r") as f:
        lines = f.readlines()
        lines = [line.split("CONSTANT_")[1].strip() for line in lines if "CONSTANT_" in line]

    return list(set(lines))


def dump_output(output_path, data):
    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)
