# SKANF Quick Start

This document covers everything an evaluator or new user needs to run the pipeline end-to-end, and interpret the outputs. For a high-level description of the project, see the [README](./README.md).

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Inputs & Outputs](#inputs--outputs)
3. [Troubleshooting](#troubleshooting)

---

## Quick Start

> **For first-time users:** we provide a deliberately vulnerable [demo contract](https://sepolia.etherscan.io/address/0x51006779Ac130AaBCDb49b1210016eeb9ade85A2) on the Ethereum Sepolia testnet for an end-to-end exercise. The demo contract uses calldata-controlled control flow before making an ERC20 transfer.
>
> Demo contract on Sepolia:
>
> ```text
> 0x51006779Ac130AaBCDb49b1210016eeb9ade85A2
> ```
>
> If `--block` is omitted, SKANF uses the latest block by default. You may also pass `--block <DEMO_BLOCK>` to test the demo contract at a specific block, where `<DEMO_BLOCK>` is the deployment block or any later Sepolia block where the contract already exists on-chain.
>
> Make sure your RPC endpoint points to the Sepolia testnet.

Run the detector:

```shell
# baseline
cd check_contracts
python3 main.py --address 0x51006779Ac130AaBCDb49b1210016eeb9ade85A2 --mode eval_baseline

# seeded approach
python3 main.py --address 0x51006779Ac130AaBCDb49b1210016eeb9ade85A2  --hash 0x7084d476018f68e7dfee9ecde32f352843c81e44d52bdfa2ecb8003bde9b1f9b  --mode eval_concolic
```

If the detector finds a vulnerable call (`output_eval_baseline.json` contains a non-empty `verified` array), run the exploit generator:

```shell
# generate exploit, and the target ERC-20 token is Sepolia USDC (0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238)
cd ../automatic_exploit_generation
python3 run.py --contract 0x51006779Ac130AaBCDb49b1210016eeb9ade85A2 --token 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238
```

A successful exploit is written to `Exploits/<addr>.<block>.json`. See [Inputs & Outputs](#inputs--outputs) for the schema.

---

## Inputs & Outputs

### On-disk layout

By default, all analysis artifacts live under `AnalysisData/` at the repo root (override with `SKANF_WORKDIR`). For a contract at address `0xABCD...`:

```
AnalysisData/
└── 0xABC/                         # first 5 hex chars (incl. "0x") of the address
    └── 0xABCD.../                   # full checksummed address
        ├── contract.hex           # bytecode fetched from chain
        ├── contract.tac           # Gigahorse three-address code (TAC) IR
        ├── *.csv                  # Gigahorse fact tables (call edges, jump tables, ...)
        └── output_<mode>.json     # SKANF detector verdict
```

Exploits land under `Exploits/` at the repo root (override with `SKANF_EXPLOIT_DIR`).

### Schema of `output_<mode>.json`

```jsonc
{
  "verified": [                            // calls SKANF could reach and control
    {
      "caller": "0x0000...0001",           // attacker address used during analysis
      "origin": "0x0000...0001",           // tx.origin used during analysis
      "entry_point": "0xa9059cbb",         // 4-byte selector of the public function reaching the call
      "classification": "NA",              // 2-char tag: contract-target / function-target controllability.
                                           // Letter 1: N=static/known, A=attacker-controlled.
                                           // Letter 2: same, for the function selector at the inner call.
      "classification_type": "SD",         // S=static, D=dynamic; how the classification was determined.
      "contract_target": "0xdAC...7",      // target token contract (e.g., USDT), or "*" if attacker-controlled
      "function_sig_target": "0xa9059cbb", // selector at the inner call, or "*" if attacker-controlled
      "destination": "*",                  // attacker-controllable destination, or concrete address
      "destination_offset": 0,             // calldata word index that maps to `destination`
      "amount": "*",                       // attacker-controllable amount, or concrete value
      "amount_offset": 1,
      "calldata": "0xa9059cbb...",         // concrete calldata that reaches the call
      "calldata_size": 68,
      "sensitive": true,                   // matches a SENSITIVE_SIGNATURE on a SENSITIVE_ADDRESS
      "verified": true,                    // path-feasibility check confirms the call is reachable
      "call_tac_id": "0x1f7",              // Gigahorse statement id of the CALL
      "result": "SUCCESS",
      "analysis_time": 12.34
    }
  ],
  "unverified": [ /* same shape, for calls that could not be confirmed reachable */ ],
  "process_time": 173.5                    // total wall-clock seconds (top-level only)
}
```

The set of "sensitive" tokens lives in [`constants/address.json`](constants/address.json) (keyed by network) and the set of "sensitive" function selectors in [`constants/signature.json`](constants/signature.json). Both are read at detector startup; edit them to add or remove watch-list entries.

### Schema of an exploit file

```jsonc
{
  "caller": "0x0000...0001",
  "origin": "0x0000...0001",
  "calldata": "0xa9059cbb...",   // calldata that, when sent by `caller`, triggers the sensitive call
  "block_number": 20000000
}
```

---

## Troubleshooting

**`RuntimeError: Could not connect to RPC at ...`** — `WEB3_PROVIDER` is unset or unreachable. Export a working endpoint and retry. SKANF performs the connectivity check at import time so misconfiguration fails fast.

**`Gigahorse analysis failed on 0x...`** — Gigahorse timed out (default 15 min) or could not decompile the bytecode. The contract address is appended to `gigahorse_fails.txt`. Try a different block, or set a longer timeout by editing [`check_contracts/constants.py`](check_contracts/constants.py).

**`No CALL(s) have been found in the contract`** — The target has no external `CALL` instructions reachable from any public function — nothing for SKANF to analyze.

**`output_<mode>.json` exists but `verified` is empty** — SKANF found sensitive calls but could not confirm any of them are reachable from an attacker's calldata. The unverified array still has details for manual inspection.

**RPC rate-limit errors during analysis** — Free-tier providers throttle archive requests. Either upgrade the tier or point `WEB3_PROVIDER` at a local archive node (Erigon / Reth).
