<div align="center">
    <img src="./assets/logo.png" align="right" alt="logo" width="400px"/>
</div>

# SKANF

[![arXiv](https://img.shields.io/badge/arXiv-2504.13398-b31b1b?logo=arxiv)](https://arxiv.org/abs/2504.13398)
[![Docker Image](https://img.shields.io/badge/skanf:latest-blue?logo=docker)](https://hub.docker.com/r/dockerofsyang/skanf)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SKANF is a static + symbolic analysis tool that detects **asset-management vulnerabilities** in **closed-source / obfuscated EVM smart contracts** and automatically synthesizes exploit calldata for the bugs it finds.

The tool accompanies the paper *Insecurity Through Obscurity: Veiled Vulnerabilities in Closed-Source Contracts* (ACM CCS 2026).

---

## Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Getting Started](#getting-started)
5. [Usage](#usage)
6. [Environment Variables](#environment-variables)
7. [Academic Use](#academic-use)
8. [Acknowledgments](#acknowledgments)
9. [License](#license)

---

## Overview

SKANF takes the **bytecode of a deployed contract** fetched from an EVM JSON-RPC endpoint and reports any **sensitive external calls** that an attacker can reach and control. A sensitive call is, for example, an ERC-20 `transfer`, `transferFrom`, or `approve` targeting a well-known asset such as USDT or WBTC, where one or more of `{destination, amount, target token, function selector}` is influenced by attacker-controlled calldata.

The pipeline has two phases:

| Phase | Entry point | What it does |
|------|------|------|
| **Detection** | [`check_contracts/main.py`](check_contracts/main.py) | Lift bytecode with Gigahorse → enumerate `CALL`s → symbolic execution + taint analysis → path-feasibility check → emit verdict JSON. |
| **Exploit generation** | [`automatic_exploit_generation/run.py`](automatic_exploit_generation/run.py) | Read the detector's verdict, synthesize concrete calldata that triggers the call, and replay it on a forked EVM to confirm it works. |

The output of the detection phase is a JSON file listing **verified** and **unverified** vulnerable calls. The exploit phase produces a single JSON file per successful exploit under the exploits directory.

---

## System Requirements

| | Minimum | Notes |
|---|---|---|
| OS | Linux x86_64 (Ubuntu 20.04/22.04/24.04 tested) | macOS and Windows are supported via Docker Desktop. |
| RAM | 8 GB | For large bytecode, both Gigahorse analysis and symbolic execution can be memory-intensive and may require more than 8 GB of RAM. |
| Disk | 5 GB free | The Docker image is ~1.2 GB; Gigahorse output adds ~2 MB per contract. |
| Python | 3.10 (bundled in the image) | Only relevant if installing locally. |
| Docker | 20.10+ | Recommended; the pre-built image works out of the box. |
| RPC | JSON-RPC endpoint | A local archive node is recommended but not required, especially for analyses at older blocks. For basic testing, [Tenderly](https://dashboard.tenderly.co/)'s free plan is sufficient. |

---

## Installation

### Option A — Pre-built Docker image (recommended)

```shell
docker pull dockerofsyang/skanf:latest
```

Configure your RPC endpoint and network, then drop into a shell inside the container:

```shell
export WEB3_PROVIDER="https://ethereum-mainnet.gateway.tenderly.co/<YOUR_TENDERLY_NODE_ACCESS_KEY>" # or your archive node
export NETWORK=ETH
export SKANF_IMAGE=dockerofsyang/skanf:latest

docker run --rm -it --network host \
  -e WEB3_PROVIDER="$WEB3_PROVIDER" \
  -e NETWORK="$NETWORK" \
  "$SKANF_IMAGE" \
  bash
```

> We tested SKANF with [Tenderly](https://dashboard.tenderly.co/). Tenderly's free plan is sufficient for basic testing. `--network host` is Linux-specific and is only needed when the container must reach an RPC node running on `localhost:8545`. On macOS / Windows, omit `--network host` and pass a remote RPC URL via `WEB3_PROVIDER`.

### Option B — Build the Docker image from source

```shell
docker build -t skanf:latest .
export SKANF_IMAGE=skanf:latest
# then `export ...` and `docker run ...` as in Option A
```

The [`Dockerfile`](Dockerfile) provisions Ubuntu 20.04, Miniconda + Python 3.10, Soufflé 2.4, and clones the SKANF-compatible [greed-skanf](https://github.com/hackingdecentralized/greed-skanf) fork at build time.

### Option C — Local install (advanced)

SKANF depends on **custom forks** of [`greed`](https://github.com/hackingdecentralized/greed-skanf) and [`Gigahorse`](https://github.com/hackingdecentralized/gigahorse-skanf). Install those first. Their `setup.sh` scripts handle the toolchain. Then run:

```shell
pip install -r requirements.txt
export WEB3_PROVIDER="https://ethereum-mainnet.gateway.tenderly.co/<YOUR_TENDERLY_NODE_ACCESS_KEY>"
export NETWORK=ETH
```

`WEB3_PROVIDER` must point to a reachable Ethereum JSON-RPC endpoint. A local archive node is recommended when available, especially for analyses at older blocks, but [Tenderly](https://dashboard.tenderly.co/)'s free plan is sufficient for basic testing. If `WEB3_PROVIDER` is unset or unreachable, SKANF raises a `RuntimeError` at startup with the offending URL.

---

## Getting Started

See **[quickstart.md](./quickstart.md)** for:

- How to quickly run SKANF
- On-disk layout and the schema of every output file

---

## Usage

### Detection — `check_contracts/main.py`

| Flag | Required | Type | Description |
|---|---|---|---|
| `--address` | yes | hex string | Contract address to analyze, checksummed or lowercase. |
| `--block` | no | int  | Block number at which to fetch the bytecode. Defaults to latest when omitted. |
| `--mode` | no | string | Output suffix; the detector writes `output_<mode>.json`. This is useful for keeping baseline and concolic results side-by-side. Defaults to `concolic` if `--hash` is set, otherwise `baseline`. |
| `--hash` | no | tx hash | Run the **concolic** path: replay the historical transaction `<hash>` and check only the calls it touched. Without `--hash`, the detector runs purely symbolic exploration over all reachable calls. |

Common invocations:

```shell
# Pure symbolic, baseline output filename
python3 main.py --address 0xABC... --block 20000000 --mode eval_baseline

# Seeded symbolic, seeded input comes from a historical transaction
python3 main.py --address 0xABC... --block 20000000 \
  --hash 0xdef... --mode eval_concolic
```

### Exploit generation — `automatic_exploit_generation/run.py`

| Flag | Required | Type | Description |
|---|---|---|---|
| `--contract` | yes | hex string | The contract address that was previously analyzed by the detector. |
| `--block` | no | int | Block at which to validate the synthesized exploit. Defaults to latest when omitted. |

The exploit generator reads `output_eval_baseline.json` produced by the detection phase, walks its `verified` array, symbolically generates calldata that satisfies each verified call's preconditions, and replays the calldata against a forked EVM to confirm balance changes. Successful exploits are written to `Exploits/<contract>.<block>.json`.

---

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `WEB3_PROVIDER` | `http://127.0.0.1:8545` | Ethereum JSON-RPC endpoint. We tested SKANF with local archive node and [Tenderly](https://dashboard.tenderly.co/); its free plan is sufficient for basic testing. Analyses at older blocks may require RPC support for historical state at that block. |
| `NETWORK` | `ETH` | Selects the sensitive-address list from [`constants/address.json`](constants/address.json). For non-ETH networks, the PoA middleware is injected automatically. |
| `SKANF_WORKDIR` | `<repo>/AnalysisData` | Where Gigahorse output and detector verdicts are stored. |
| `SKANF_EXPLOIT_DIR` | `<repo>/Exploits` | Where synthesized exploits are stored. |

---

## Academic Use

If you use SKANF in academic work, please cite:

```bibtex
@inproceedings{yang2026insecurity,
  title={Insecurity Through Obscurity: Veiled Vulnerabilities in Closed-Source Contracts},
  author={Yang, Sen and Qin, Kaihua and Yaish, Aviv and Zhang, Fan},
  booktitle={Proceedings of the 2026 ACM SIGSAC Conference on Computer and Communications Security},
  year={2026}
}
```

---

## Acknowledgments

SKANF builds on two excellent EVM bytecode analysis projects. Please consider citing them as well.

### [greed](https://github.com/ucsb-seclab/greed/)

Symbolic execution over EVM bytecode.

<details>
<summary>BibTeX entries for papers related to greed</summary>

```bibtex
@inproceedings{gritti2023confusum,
  title={Confusum contractum: confused deputy vulnerabilities in ethereum smart contracts},
  author={Gritti, Fabio and Ruaro, Nicola and McLaughlin, Robert and Bose, Priyanka and Das, Dipanjan and Grishchenko, Ilya and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={32nd USENIX Security Symposium (USENIX Security 23)},
  pages={1793--1810},
  year={2023}
}

@inproceedings{ruaro2024crush,
  title={Not your Type! Detecting Storage Collision Vulnerabilities in Ethereum Smart Contracts},
  author={Ruaro, Nicola and Gritti, Fabio and McLaughlin, Robert and Grishchenko, Ilya and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={Network and Distributed Systems Security (NDSS) Symposium 2024},
  year={2024}
}

@inproceedings{ruaro2025approve,
  title={Approve Once, Regret Forever: On the Exploitation of Ethereum's $\{$Approve-TransferFrom$\}$ Ecosystem},
  author={Ruaro, Nicola and Gritti, Fabio and Meng, Dongyu and McLaughlin, Robert and Grishchenko, Ilya and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={34th USENIX Security Symposium (USENIX Security 25)},
  pages={1281--1298},
  year={2025}
}
```

</details>

### [Gigahorse](https://github.com/nevillegrech/gigahorse-toolchain/)

Decompiles low-level EVM bytecode into a higher-level three-address representation.

<details>
<summary>BibTeX entries for papers related to Gigahorse</summary>

```bibtex
@inproceedings{grech2019gigahorse,
  title={Gigahorse: thorough, declarative decompilation of smart contracts},
  author={Grech, Neville and Brent, Lexi and Scholz, Bernhard and Smaragdakis, Yannis},
  booktitle={2019 IEEE/ACM 41st International Conference on Software Engineering (ICSE)},
  pages={1176--1186},
  year={2019},
  organization={IEEE}
}

@article{grech2022elipmoc,
  title={Elipmoc: Advanced decompilation of ethereum smart contracts},
  author={Grech, Neville and Lagouvardos, Sifis and Tsatiris, Ilias and Smaragdakis, Yannis},
  journal={Proceedings of the ACM on Programming Languages},
  volume={6},
  number={OOPSLA1},
  pages={1--27},
  year={2022},
  publisher={ACM New York, NY, USA}
}

@article{lagouvardos2025incredible,
  title={The Incredible Shrinking Context... in a decompiler near you},
  author={Lagouvardos, Sifis and Bollanos, Yannis and Grech, Neville and Smaragdakis, Yannis},
  journal={Proceedings of the ACM on Software Engineering},
  volume={2},
  number={ISSTA},
  pages={1350--1373},
  year={2025},
  publisher={ACM New York, NY, USA}
}
```

</details>

---

## License

SKANF is released under the [MIT License](LICENSE) © 2026 [Decentralized Systems Group at Yale](https://www.fanzhang.me/group/), except for third-party components, which remain under their original licenses.