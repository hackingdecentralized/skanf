import json
import os

# Global variables
BLOCK_REF = -1

# Repo root, resolved from this file so paths work regardless of cwd.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

# Analysis output directory. Override with SKANF_WORKDIR.
WORKDIR = os.environ.get("SKANF_WORKDIR") or os.path.join(_REPO_ROOT, "AnalysisData")

# Bundled JSON constants (signature.json, address.json) live in <repo>/constants.
CONSTANT_DIR = os.path.join(_REPO_ROOT, "constants")

# 30 minutes for taint analysis
TIMEOUT_TAINT_ANALYSIS = 60 * 2

# This script is exported by greed during the installation
GIGAHORSE_ANALYSIS_SCRIPT = "analyze_hex.sh"
GIGAHORSE_TIMEOUT = "15m"
GIGAHORSE_FAILS = "./gigahorse_fails.txt"


# Sensitive functions and contracts
sensitive_original_signatures = set()
with open(os.path.join(CONSTANT_DIR, "signature.json"), "r") as f:
    signatures = json.load(f)
    sensitive_original_signatures.update(signatures)

SENSITIVE_SIGNATURES = sensitive_original_signatures | set([i[2::] for i in sensitive_original_signatures])

sensitive_original_addresses = set()
with open(os.path.join(CONSTANT_DIR, "address.json"), "r") as f:
    network = os.environ.get('NETWORK', "ETH")
    addresses = json.load(f)
    address_in_network = addresses.get(network, [])
    sensitive_original_addresses.update(address_in_network)

SENSITIVE_ADDRESSES = sensitive_original_addresses | set([i.lower() for i in sensitive_original_addresses])

# Test address
TEST_SENDER = "0x0000000000000000000000000000000000000001"

# Colors for the terminal
class bcolors:
    # Text colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    # Background colors:
    GREYBG = '\033[100m'
    REDBG = '\033[101m'
    GREENBG = '\033[102m'
    YELLOWBG = '\033[103m'
    BLUEBG = '\033[104m'
    PINKBG = '\033[105m'
    CYANBG = '\033[106m'
