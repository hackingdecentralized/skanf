from dataclasses import dataclass
from typing import Any


# Sensitive functions and contracts
sensitive_original_signatures = set([
    "0xa9059cbb",
    "0x095ea7b3",
    "0x23b872dd"
])

SENSITIVE_SIGNATURES = sensitive_original_signatures | set([i[2::] for i in sensitive_original_signatures])

sensitive_original_addresses = set([
    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", # WETH
    "0xdAC17F958D2ee523a2206206994597C13D831ec7", # USDT
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", # USDC
    "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", # WBTC
    "0x6B175474E89094C44Da98b954EedeAC495271d0F", # DAI
    "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", # UNI
    "0x514910771AF9Ca656af840dff83E8264EcF986CA", # LINK
    "0xB8c77482e45F1F44dE1745F52C74426C631bDD52", # BNB
])

SENSITIVE_ADDRESSES = sensitive_original_addresses | set([i.lower() for i in sensitive_original_addresses])


class ConcreteCall:
    def __init__(self, origin_addr, from_addr, to_addr, calldata, call_value, block_number):
        self.origin = origin_addr
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.calldata = calldata
        self.value = call_value
        self.block_number = block_number

    def __str__(self):
        return f"Call to {self.to_addr} from {self.from_addr} with value {self.value} and data {self.calldata} in block {self.block_number}"
    
    def __repr__(self):
        return self.__str__()


@dataclass
class CallParam:
    name: str
    value: Any
    controlable: bool
    offset_in_calldata: int


class ConcreteCallStmt:
    def __init__(self, call_stmt, init_ctx):
        self.stmt = call_stmt
        self.target_contract: CallParam = None
        self.func_selector: CallParam = None
        self.parameters = {}
        self.sensitive = False
        self.original_calldata = None
        self.calldata = None
        self.calldata_size = 0
        self.entry_point = None
        self.init_ctx = init_ctx
        self.caller = init_ctx.get("CALLER", None)
        self.origin = init_ctx.get("ORIGIN", None)
        self.traces = []
    
    def update_target_contract(self, target_contract, contract_controlable, offset_in_calldata):
        self.target_contract = CallParam("target_contract", target_contract, contract_controlable, offset_in_calldata)

    def update_function_selector(self, func_selector, func_controlable, offset_in_calldata):
        self.func_selector = CallParam("func_selector", func_selector, func_controlable, offset_in_calldata)

    def update_parameter(self, parameter_position, parameter_value, parameter_controlable, offset_in_calldata):
        self.parameters[parameter_position] = CallParam(f"parameter_{parameter_position}", parameter_value, parameter_controlable, offset_in_calldata)

    def check_sensitivity(self):
        contract_sensitive = self.target_contract.controlable or self.target_contract.value in SENSITIVE_ADDRESSES
        func_sensitive = self.func_selector.controlable or self.func_selector.value in SENSITIVE_SIGNATURES
        self.sensitive = contract_sensitive and func_sensitive
    
    def set_calldata(self, original_calldata, calldata, calldata_size):
        self.original_calldata = original_calldata
        self.calldata = calldata
        self.calldata_size = calldata_size
        self.entry_point = calldata[:8]
    
    def log_traces(self, traces):
        self.traces = traces
    
    def dump(self):
        output = {
            "caller": self.caller,
            "origin": self.origin,
            "calldata_size": self.calldata_size,
            "contract_target": self.target_contract.value,
            "function_sig_target": self.func_selector.value,
            "calldata": self.calldata,
            "original_calldata": self.original_calldata,
            "entry_point": self.entry_point,
            "result": "SUCCESS",
            "sensitive": self.sensitive,
            "verified": False,
            "call_tac_id": self.stmt.id,
            "traces": self.traces
        }


        if self.func_selector.value == "0x23b872dd":
            output["destination"] = self.parameters.get(1, None).value if 1 in self.parameters else None
            output["amount"] = self.parameters.get(2, None).value if 2 in self.parameters else None
            output["destination_offset"] = 1
            output["amount_offset"] = 2
        else:
            # Default behavior for other function signatures
            output["destination"] = self.parameters.get(0, None).value if 0 in self.parameters else None
            output["amount"] = self.parameters.get(1, None).value if 1 in self.parameters else None
            output["destination_offset"] = 0
            output["amount_offset"] = 1

        return output