# Test Contracts

This directory contains small example contracts used for testing SKANF.

## DynamicCalldataJump

`DynamicCalldataJump.huff` is an intentionally vulnerable Huff contract with control flow obfuscation. It uses a calldata-controlled dynamic jump before making an ERC20 transfer.

The contract is designed as a minimal test case for tools that analyze closed-source or obfuscated EVM bytecode. It is not meant for production use.

### Behavior

The contract expects calldata with the following layout:

```text
0x00..0x03   ignored function selector
0x04..0x23   jump destination
0x24..0x43   ERC20 token address
0x44..0x63   recipient address
```

At runtime, the contract loads the jump destination from calldata and jumps to it:

```text
0x04 calldataload
jump
```

For the provided bytecode, the valid transfer entry point is at program counter `0x04`. After reaching this entry point, the contract calls:

```solidity
IERC20(token).transfer(recipient, 1)
```

This transfers `1` smallest token unit from the contract's own ERC20 balance to the recipient address.

### Why this contract is vulnerable

The contract is deliberately vulnerable because user-controlled calldata affects the control-flow target. It also performs an ERC20 transfer without any authorization check. As a result, anyone can call the contract and ask it to transfer `1` token unit from the contract's balance.

This makes the contract useful as a small end-to-end demo for detecting calldata-controlled control flow and unauthorized asset transfer behavior.

### Compile

Install the Huff compiler, then compile the contract:

```shell
huffc DynamicCalldataJump.huff --bytecode
```

The compiler output is the creation bytecode that can be deployed on an EVM-compatible chain.

### Demo deployment

A demo instance is deployed on the Ethereum Sepolia testnet:

```text
0x51006779Ac130AaBCDb49b1210016eeb9ade85A2
```

Make sure your RPC endpoint points to Sepolia when analyzing this address.
