#!/usr/bin/env python3
"""II17 - AEGIS Control Plane CLI (aegisctl)

Provides operator commands to manage the AEGIS NIDS service:
  status, start, stop, restart, rules list/reload, incidents list,
  flows dump, federation status, config validate/reload, logs tail,
  metrics snapshot, backup, restore, health-check, version.

Usage:
    python tools/aegisctl.py status
    python tools/aegisctl.py rules list
    python tools/aegisctl.py incidents list --severity alert
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

# AEGIS control socket (Windows: named pipe \\.\pipe\aegis_control)
# Linux/test: TCP localhost:5117
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5117
DEFAULT_NAMED_PIPE = r"\\.\pipe\aegis_control"


class AegisCtlError(Exception):
    pass


class AegisClient:
    """Client that talks to the AEGIS control plane."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def _send(self, command: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if os.name == "nt":
            # Windows: use named pipe
            try:
                import win32file  # type: ignore
                import win32pipe  # type: ignore
            except ImportError:
                # Fallback to TCP for testing
                return self._send_tcp(command, payload)
            try:
                handle = win32file.CreateFile(
                    DEFAULT_NAMED_PIPE,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0, None, win32file.OPEN_EXISTING, 0, None
                )
                req = json.dumps({"command": command, "payload": payload or {}}).encode("utf-8")
                win32file.WriteFile(handle, req)
                _, resp = win32file.ReadFile(handle, 65536)
                win32file.CloseHandle(handle)
                return json.loads(resp.decode("utf-8"))
            except Exception as e:
                raise AegisCtlError(f"named pipe error: {e}")
        return self._send_tcp(command, payload)

    def _send_tcp(self, command: str, payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
                req = json.dumps({"command": command, "payload": payload or {}}).encode("utf-8")
                s.sendall(req)
                chunks = []
                while True:
                    data = s.recv(65536)
                    if not data:
                        break
                    chunks.append(data)
                resp = b"".join(chunks)
                return json.loads(resp.decode("utf-8"))
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            raise AegisCtlError(f"connection error: {e}")


def cmd_status(args: argparse.Namespace) -> int:
    try:
        client = AegisClient()
        resp = client._send("status")
    except AegisCtlError as e:
        print(f"âŒ AEGIS daemon not reachable: {e}", file=sys.stderr)
        return 2
    if not resp.get("ok"):
        print(f"âŒ {resp.get('error', 'unknown error')}", file=sys.stderr)
        return 1
    data = resp.get("data", {})
    print(f"AEGIS NIDS v{data.get('version', '?')}")
    print(f"  Status:        {data.get('state', 'unknown')}")
    print(f"  Uptime:        {data.get('uptime_sec', 0)}s")
    print(f"  Packets:       {data.get('packets_captured', 0):,}")
    print(f"  Flows active:  {data.get('flows_active', 0):,}")
    print(f"  Incidents:     {data.get('incidents_open', 0):,}")
    print(f"  Watchdog:      {data.get('watchdog_alerts', 0):,} alerts")
    if data.get("degraded"):
        print(f"  âš  Degraded: {data.get('degrade_reason')}")
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    if os.name == "nt":
        subprocess.run(["sc", "start", "AegisNids"], check=False)
    else:
        subprocess.run(["systemctl", "start", "aegis-nids"], check=False)
    print("âœ… AEGIS NIDS start signal sent")
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    if os.name == "nt":
        subprocess.run(["sc", "stop", "AegisNids"], check=False)
    else:
        subprocess.run(["systemctl", "stop", "aegis-nids"], check=False)
    print("âœ… AEGIS NIDS stop signal sent")
    return 0


def cmd_restart(args: argparse.Namespace) -> int:
    cmd_stop(args)
    time.sleep(1)
    cmd_start(args)
    return 0


def cmd_rules_list(args: argparse.Namespace) -> int:
    client = AegisClient()
    resp = client._send("rules.list")
    rules = resp.get("data", {}).get("rules", [])
    if not rules:
        print("(no rules loaded)")
        return 0
    print(f"{'ID':<8} {'Sev':<8} {'Action':<10} {'Pattern':<40}")
    for r in rules:
        print(f"{r.get('id', 0):<8} {r.get('severity', '?'):<8} {r.get('action', '?'):<10} {r.get('pattern', '?')[:40]:<40}")
    return 0


def cmd_rules_reload(args: argparse.Namespace) -> int:
    client = AegisClient()
    resp = client._send("rules.reload")
    if resp.get("ok"):
        print(f"âœ… Reloaded {resp['data'].get('rules_loaded', 0)} rules")
        return 0
    print(f"âŒ {resp.get('error')}", file=sys.stderr)
    return 1


def cmd_incidents(args: argparse.Namespace) -> int:
    client = AegisClient()
    resp = client._send("incidents.list", {"severity_min": args.severity})
    incs = resp.get("data", {}).get("incidents", [])
    if not incs:
        print("(no open incidents)")
        return 0
    for i in incs:
        print(f"#{i.get('id', 0):<6} sev={i.get('severity'):<8} score={i.get('score', 0):<6} src={i.get('src_ip'):<12} flow={i.get('flow_id')}")
    return 0


def cmd_federation(args: argparse.Namespace) -> int:
    client = AegisClient()
    resp = client._send("federation.status")
    data = resp.get("data", {})
    print(f"Federation: {'enabled' if data.get('enabled') else 'disabled'}")
    if data.get("enabled"):
        print(f"  Self ID:    {data.get('self_id')}")
        print(f"  Role:       {data.get('role')}")
        print(f"  Leader:     {data.get('leader_id')}")
        print(f"  Nodes:      {data.get('node_count', 0)}")
        print(f"  Heartbeat:  {data.get('heartbeat_ms', 1000)}ms")
    return 0


def cmd_metrics(args: argparse.Namespace) -> int:
    client = AegisClient()
    resp = client._send("metrics.snapshot")
    data = resp.get("data", {})
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    for key, value in data.items():
        print(f"  {key:<32} {value}")
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    client = AegisClient()
    try:
        resp = client._send("health.check")
    except AegisCtlError as e:
        print(f"âŒ Daemon not reachable: {e}")
        return 2
    checks = resp.get("data", {}).get("checks", [])
    all_ok = True
    for c in checks:
        status = "âœ…" if c.get("ok") else "âŒ"
        print(f"  {status} {c.get('name')}: {c.get('detail', '')}")
        if not c.get("ok"):
            all_ok = False
    return 0 if all_ok else 1


def cmd_version(args: argparse.Namespace) -> int:
    print("AEGIS NIDS v5.0+ (aegisctl)")
    print(f"  CLI build: 2026-09-07")
    print(f"  Protocol version: 5")
    return 0


def cmd_logs_tail(args: argparse.Namespace) -> int:
    log_path = Path(os.environ.get("AEGIS_LOG_PATH", "logs/aegis.log"))
    if not log_path.exists():
        print(f"Log file not found: {log_path}", file=sys.stderr)
        return 1
    with log_path.open("r", encoding="utf-8") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            print(line, end="")


def cmd_backup(args: argparse.Namespace) -> int:
    subprocess.run([sys.executable, "tools/backup_recovery.py", "backup", "--output", args.output], check=False)
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    subprocess.run([sys.executable, "tools/backup_recovery.py", "restore", "--input", args.input], check=False)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS NIDS control plane CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="Show daemon status")
    sub.add_parser("start", help="Start AEGIS service")
    sub.add_parser("stop", help="Stop AEGIS service")
    sub.add_parser("restart", help="Restart AEGIS service")

    p_rules = sub.add_parser("rules", help="Rule management")
    rules_sub = p_rules.add_subparsers(dest="rules_cmd", required=True)
    rules_sub.add_parser("list", help="List loaded rules")
    rules_sub.add_parser("reload", help="Reload rules from disk")

    p_inc = sub.add_parser("incidents", help="Incident management")
    p_inc.add_argument("--severity", default="warning", help="Minimum severity (default: warning)")

    sub.add_parser("federation", help="Federation status")

    p_met = sub.add_parser("metrics", help="Metrics snapshot")
    p_met.add_argument("--json", action="store_true", help="Output JSON")

    sub.add_parser("health", help="Run health check")
    sub.add_parser("version", help="Show version")

    p_log = sub.add_parser("logs", help="Log management")
    log_sub = p_log.add_subparsers(dest="log_cmd", required=True)
    log_sub.add_parser("tail", help="Tail log file")

    p_b = sub.add_parser("backup", help="Backup state")
    p_b.add_argument("--output", default="aegis_backup.zip")
    p_r = sub.add_parser("restore", help="Restore state")
    p_r.add_argument("--input", required=True)

    args = parser.parse_args()
    cmd_map = {
        "status": cmd_status,
        "start": cmd_start,
        "stop": cmd_stop,
        "restart": cmd_restart,
        "rules": lambda a: cmd_rules_list(a) if a.rules_cmd == "list" else cmd_rules_reload(a),
        "incidents": cmd_incidents,
        "federation": cmd_federation,
        "metrics": cmd_metrics,
        "health": cmd_health,
        "version": cmd_version,
        "logs": lambda a: cmd_logs_tail(a) if a.log_cmd == "tail" else 1,
        "backup": cmd_backup,
        "restore": cmd_restore,
    }
    handler = cmd_map.get(args.cmd)
    if handler is None:
        parser.print_help()
        return 1
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
