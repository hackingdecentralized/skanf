import json
import os
import requests

from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware

from .concrete_call import ConcreteCall


if os.environ.get('WEB3_PROVIDER', None):
    web3_provider_url = os.environ['WEB3_PROVIDER']
else:
    web3_provider_url = 'http://127.0.0.1:8545'


w3 = Web3(HTTPProvider(web3_provider_url))
if os.environ.get('NETWORK', "ETH") != "ETH":
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)


def get_internal_calls(tx_hash, contract_addr):
    tx_detail = w3.eth.get_transaction(tx_hash)
    origin = w3.to_checksum_address(tx_detail['from'])
    target = w3.to_checksum_address(contract_addr)
    block_number = tx_detail['blockNumber']

    payload = json.dumps({
        "method": "trace_replayTransaction",
        "params": [
            tx_hash,
            [
                "trace",
            ]
        ],
        "id": 1,
        "jsonrpc": "2.0"
    })
    headers = {
        'Content-Type': 'application/json'
    }


    res = requests.post(web3_provider_url, headers=headers, data=payload)
    res = res.json()

    calls = []
    for call in res['result']['trace']:
        if call['type'] != 'call' or call['action']['callType'] != 'call': # only interested in calls
            continue
        call_from = w3.to_checksum_address(call['action']['from'])
        call_to = w3.to_checksum_address(call['action']['to'])

        function_selector = call['action']['input'][:10].lower()
        if call_to != target or call['action']['input'] == '0x': # only interested in internal calls to the target contract from a different contract
            continue
        calls.append(call)

    return [ConcreteCall(origin, call['action']['from'], call['action']['to'], call['action']['input'], call['action']['value'], block_number) for call in calls]

