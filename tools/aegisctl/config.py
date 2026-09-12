"""AEGIS NIDS CLI configuration and constants."""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Network
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5117
DEFAULT_NAMED_PIPE = r"\\.\pipe\aegis_control"
AGGREGATOR_PORT = 9200
BRAIN_UDP_PORT = 9999

# Components
COMPONENTS = ["bridge", "core", "brain", "nose", "mouth", "aggregator"]

SUBSYSTEMS = [
    {
        "name": "bridge",
        "description": "Bridge (C++) -- IPC hub + Packet Parser + DEFCON",
        "exe": "aegis_bridge.exe",
        "required": True,
    },
    {
        "name": "core",
        "description": "Core (Zig) -- Tier-1 Aho-Corasick pattern matching",
        "exe": "aegis_nids.exe",
        "required": True,
    },
    {
        "name": "brain",
        "description": "Brain (Python) -- Tier-2 regex + IPS policy enforcement",
        "exe": None,
        "script": "brain/windows_brain.py",
        "required": True,
    },
    {
        "name": "nose",
        "description": "Nose (Go) -- 3 Goroutines perf monitor + DEFCON",
        "exe": "aegis-nose.exe",
        "required": True,
    },
    {
        "name": "mouth",
        "description": "Mouth (Rust) -- behavioral validation + DEFCON display",
        "exe": "windows_sec_monitor.exe",
        "required": True,
    },
]

# Paths
LOGS_DIR = REPO_ROOT / "logs"
PID_DIR = LOGS_DIR / "pids"
NDJSON_LOG = LOGS_DIR / "aegis_core.ndjson"
ANOMALOUS_LOG = LOGS_DIR / "anomalous.json"
DAEMON_LOG = LOGS_DIR / "daemon.log"
BLOCKED_IPS_FILE = LOGS_DIR / "blocked_ips.json"
QUARANTINE_FILE = LOGS_DIR / "quarantine.json"
PEP_STATE_FILE = LOGS_DIR / "runtime" / "pep_state.json"
CANARY_RESULTS_DIR = LOGS_DIR / "runtime"

CONFIG_DIR = REPO_ROOT / "config"
RULES_FILE = CONFIG_DIR / "Rules.json"
DISABLED_RULES_FILE = CONFIG_DIR / "disabled_rules.json"
CANARY_TESTS_FILE = REPO_ROOT / "configs" / "canary_tests.json"

BUILD_MANIFEST = REPO_ROOT / "build_manifest.json"
CONTROL_AUDIT_LOG = LOGS_DIR / "control_audit.ndjson"

# RBAC Roles
ROLE_PRIVILEGED = "privileged"
ROLE_OPERATE = "operate"
ROLE_READ = "read"

# Watchdog
WATCHDOG_INTERVAL = 5
WATCHDOG_MAX_RESTARTS = 3
WATCHDOG_RESTART_WINDOW = 3600
