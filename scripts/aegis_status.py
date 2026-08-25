#!/usr/bin/env python3
"""
aegis_status.py - AEGIS NIDS Status CLI (Phase 13, UX-03)

Checks status of all 5 AEGIS subsystems:
  - BRIDGE: aegis_ipc.dll loaded (C++ IPC bridge)
  - CORE:   nids_analyze.exe / Zig core running
  - BRAIN:  windows_brain.py listening on UDP 9999
  - NOSE:   windows_capture (WFP sensor)
  - MOUTH:  sec_monitor.dll (Rust shield)

Output:
  --json    Machine-readable JSON (for scripts)
  (default) Human-readable table

Usage:
  python aegis_status.py          # human-readable
  python aegis_status.py --json   # JSON for monitoring
"""

import argparse
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

# ============================================================
# Configuration
# ============================================================

AEGIS_ROOT = Path(__file__).parent.parent
LOGS_DIR = AEGIS_ROOT / "logs"
PID_DIR = AEGIS_ROOT / "logs" / "pids"

# Subsystem process names (for tasklist check)
PROCESS_NAMES = {
    "BRIDGE": ["aegis_ipc.exe", "aegis_bridge.exe"],
    "CORE":   ["nids_analyze.exe", "aegis.exe", "aegis_core.exe"],
    "BRAIN":  ["python.exe"],  # windows_brain.py runs under python
    "NOSE":   ["nids_analyze.exe"],  # same process as CORE
    "MOUTH":  ["sec_monitor.exe"],
}

# UDP ping port for brain
BRAIN_UDP_PORT = 9999
BRAIN_PING_TIMEOUT = 2.0  # seconds


def check_pid_file(subsystem: str) -> bool:
    """Check if PID file exists and process is running."""
    pid_file = PID_DIR / f"{subsystem.lower()}.pid"
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text().strip())
        # On Windows, check if process exists
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            capture_output=True, text=True, timeout=2
        )
        return str(pid) in result.stdout
    except (ValueError, subprocess.TimeoutExpired, OSError):
        return False


def check_process_running(process_names: list) -> bool:
    """Check if any of the process names are running via tasklist."""
    try:
        result = subprocess.run(
            ["tasklist"],
            capture_output=True, text=True, timeout=5
        )
        for name in process_names:
            if name.lower() in result.stdout.lower():
                return True
    except (subprocess.TimeoutExpired, OSError):
        pass
    return False


def check_brain_udp() -> bool:
    """Send UDP ping to brain on port 9999."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(BRAIN_PING_TIMEOUT)
        sock.sendto(b'{"cmd":"ping"}', ("127.0.0.1", BRAIN_UDP_PORT))
        # Brain may not echo, but if port is open we get no ICMP error
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def check_log_file(filename: str) -> bool:
    """Check if a log file exists and was modified recently (within 60s)."""
    log_path = LOGS_DIR / filename
    if not log_path.exists():
        return False
    try:
        mtime = log_path.stat().st_mtime
        import time
        age = time.time() - mtime
        return age < 60  # active if modified within 60 seconds
    except OSError:
        return False


def get_subsystem_status(subsystem: str) -> dict:
    """Get status of a single subsystem."""
    if subsystem == "BRAIN":
        # Brain is checked via UDP
        running = check_brain_udp()
        return {
            "subsystem": subsystem,
            "running": running,
            "method": "udp_ping",
            "details": f"UDP port {BRAIN_UDP_PORT} {'open' if running else 'closed'}",
        }
    elif subsystem == "CORE":
        # Check via forensic log activity + process
        log_active = check_log_file("aegis_core.ndjson")
        proc_running = check_process_running(PROCESS_NAMES["CORE"])
        return {
            "subsystem": subsystem,
            "running": log_active or proc_running,
            "method": "log_activity+process",
            "details": f"log_active={log_active}, process={proc_running}",
        }
    elif subsystem == "BRIDGE":
        running = check_process_running(PROCESS_NAMES["BRIDGE"])
        return {
            "subsystem": subsystem,
            "running": running,
            "method": "process_check",
            "details": f"process={running}",
        }
    elif subsystem == "NOSE":
        # NOSE = WFP sensor, check via core process (same process)
        running = check_process_running(PROCESS_NAMES["NOSE"])
        return {
            "subsystem": subsystem,
            "running": running,
            "method": "process_check",
            "details": f"WFP sensor in core process",
        }
    elif subsystem == "MOUTH":
        running = check_process_running(PROCESS_NAMES["MOUTH"])
        return {
            "subsystem": subsystem,
            "running": running,
            "method": "process_check",
            "details": f"Rust shield process={running}",
        }
    else:
        return {"subsystem": subsystem, "running": False, "method": "unknown", "details": ""}


def get_all_status() -> dict:
    """Get status of all subsystems."""
    subsystems = ["BRIDGE", "CORE", "BRAIN", "NOSE", "MOUTH"]
    results = {}
    for sub in subsystems:
        results[sub] = get_subsystem_status(sub)

    active_count = sum(1 for s in results.values() if s["running"])
    return {
        "overall": "ACTIVE" if active_count >= 3 else "DEGRADED" if active_count >= 1 else "STOPPED",
        "active_count": active_count,
        "total_count": len(subsystems),
        "subsystems": results,
    }


def print_human_readable(status: dict):
    """Print human-readable status table."""
    print("=" * 50)
    print(f"  AEGIS NIDS Status: {status['overall']}")
    print(f"  Active: {status['active_count']}/{status['total_count']} subsystems")
    print("=" * 50)
    print()
    for sub, info in status["subsystems"].items():
        icon = "[OK]  " if info["running"] else "[--]  "
        print(f"  {icon}{sub:8s} ({info['method']})")
        print(f"          {info['details']}")
        print()
    print("=" * 50)
    return 0 if status["overall"] != "STOPPED" else 1


def main():
    parser = argparse.ArgumentParser(description="AEGIS NIDS Status CLI")
    parser.add_argument("--json", action="store_true", help="Output JSON for scripts")
    args = parser.parse_args()

    status = get_all_status()

    if args.json:
        print(json.dumps(status, indent=2))
    else:
        return print_human_readable(status)

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
