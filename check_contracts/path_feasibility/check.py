import argparse
import os

from ethpwn import *
from web3 import Web3

from .check_plugin import CheckPlugin


def safe_geth_poa_middleware(make_request, w3):
    def middleware(method, params):
        response = make_request(method, params)

        if method in ["eth_getBlockByHash", "eth_getBlockByNumber"]:
            if 'result' in response and response['result'] is not None:
                block = response['result']
                if 'extraData' in block:
                    original_extra_data = block['extraData']
                    block['proofOfAuthorityData'] = original_extra_data
                    
                    if len(original_extra_data) > 32:
                        block['extraData'] = original_extra_data[:32]

        return response
    return middleware


'''
# e.g.,
# python check.py --target  <CHECKSUMMED_CONTRACT_ADDRESS> --block <BLOCK_NUMBER>
 --calldata 6dbf2fa000000000000000000000000080000000000000000000000000000000000000002f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f00000000000000000000000000000000000000000000000000000000000002002f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2
 --calltacid 0x1f7
'''
def main():
    arg_parser = argparse.ArgumentParser(description='path_feasibility_validator')
    arg_parser.add_argument('--target',   type=str, required=True)
    arg_parser.add_argument('--block',    type=int, required=True)
    arg_parser.add_argument('--calldata', type=str, required=True)
    arg_parser.add_argument('--calltacid', type=str, required=True)

    args = arg_parser.parse_args()

    target = normalize_contract_address(args.target)

    a1 = get_evm_at_block(args.block)

    cp = CheckPlugin(args.calltacid)
    a1.register_plugin(cp)

    wallet_conf = get_wallet(None)

    txn_data = dict()
    txn_data['sender'] = wallet_conf.address
    txn_data['to'] = target
    txn_data['calldata'] = args.calldata
    txn_data['wallet_conf'] = get_wallet(None)

    new_txn = a1.build_new_transaction(txn_data)

    rcpt, _ = a1.apply(new_txn)

    print(a1.plugins.origin_sender_checker.call_is_reachable)


def check_call_reachability(target:str, caller:str, origin:str, block:int, calldata:str, calltacid:str):
    if os.environ.get('WEB3_PROVIDER', None):
        w3 = Web3(Web3.HTTPProvider(os.environ['WEB3_PROVIDER']))
    else:
        w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))

    if os.environ.get('NETWORK', "ETH") != "ETH":
        w3.middleware_onion.inject(safe_geth_poa_middleware, layer=0)

    context._w3 = w3

    target = normalize_contract_address(target)

    a1 = get_evm_at_block(block)

    cp = CheckPlugin(calltacid, normalize_contract_address(target), normalize_contract_address(caller), normalize_contract_address(origin), False, True)
    a1.register_plugin(cp)

    txn_data = {
        'to': target,
        'calldata': calldata,
        'sender': caller,
    }
    print(txn_data)

    new_txn = a1.build_new_transaction(txn_data)
    rcpt, status = a1.apply(new_txn)

    return a1.plugins.origin_sender_checker.call_is_reachable


if __name__ == '__main__':
    main()
