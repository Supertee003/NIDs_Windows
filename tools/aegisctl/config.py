"""AEGIS NIDS CLI configuration and constants."""
import os
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
        "exe": "dist/aegis_bridge.exe",
        "required": True,
    },
    {
        "name": "core",
        "description": "Core (Zig) -- Tier-1 Aho-Corasick pattern matching",
        "exe": "zig-out/bin/aegis_nids.exe",
        "required": True,
    },
    {
        "name": "brain",
        "description": "Brain (Python) -- Tier-2 regex analytics, advisory only, never enforces",
        "exe": None,
        "script": "brain/windows_brain.py",
        "required": True,
    },
    {
        "name": "nose",
        "description": "Nose (Go) -- 3 Goroutines perf monitor + DEFCON",
        "exe": "dist/nose_dashboard.exe",
        "required": True,
    },
    {
        "name": "mouth",
        "description": "Mouth (Rust) -- OPTIONAL standalone DEFCON display, advisory only, never linked into runtime",
        "exe": "dist/windows_sec_monitor.exe",
        "required": False,
    },
]

# Paths
# S3-01 / TEST HYGIENE item 2: tests and lab runs redirect runtime state away
# from the tracked tree. The installed service never sets AEGIS_LOGS_DIR, so
# production state stays at <repo>/logs and an operator cannot silently move it
# by exporting a variable into a shell that the SCM does not use.
LOGS_DIR = Path(os.environ.get("AEGIS_LOGS_DIR") or (REPO_ROOT / "logs"))
PID_DIR = LOGS_DIR / "pids"
NDJSON_LOG = LOGS_DIR / "aegis_core.ndjson"
ANOMALOUS_LOG = LOGS_DIR / "anomalous.json"
DAEMON_LOG = LOGS_DIR / "daemon.log"
BLOCKED_IPS_FILE = LOGS_DIR / "blocked_ips.json"
QUARANTINE_FILE = LOGS_DIR / "quarantine.json"
PEP_STATE_FILE = LOGS_DIR / "runtime" / "pep_state.json"
CANARY_RESULTS_DIR = LOGS_DIR / "runtime"

CONFIG_DIR = REPO_ROOT / "config"
# Single rule authority: configs/Rules.json is the only rule set the Zig
# detector, the Go nose classifier, the Brain and the control plane read.
# config/Rules.json is a legacy mirror kept byte-identical for packaging
# checks; nothing may load rules from it (see
# tests/security/test_single_rule_authority.py).
RULES_FILE = REPO_ROOT / "configs" / "Rules.json"
# BE-DIS-089: colocated with the canonical Rules.json so the CLI and the
# Zig engine (rule_loader.zig loadDisabledMap) read the same file.
# The old config/ (singular) path never met the engine.
DISABLED_RULES_FILE = REPO_ROOT / "configs" / "disabled_rules.json"
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
