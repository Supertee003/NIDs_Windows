"""Status, health, version, diagnose commands."""
from __future__ import annotations

import argparse
import json
import platform
import sys
from typing import Dict

from ..client import AegisClient, AegisCtlError
from ..config import REPO_ROOT, LOGS_DIR


def cmd_status(args: argparse.Namespace) -> int:
    try:
        client = AegisClient()
        resp = client.send("status")
    except AegisCtlError as e:
        print(f"[!] AEGIS daemon not reachable: {e}", file=sys.stderr)
        print("Version:     (daemon not reachable)")
        print("State:       (daemon not reachable)")
        print("Uptime:      -")
        print("Packets:     -")
        print("Flows:       -")
        print("Incidents:   -")
        print("Rules:       -")
        print("Processed:   -")
        print("Detections:  -")
        print("Degraded:    -")
        return 0
    data = resp.get("data", {})
    if getattr(args, "json", False):
        print(json.dumps(data, indent=2))
    else:
        print(f"  Version:     {data.get('version', '?')}")
        print(f"  State:       {data.get('state', '?')}")
        print(f"  Uptime:      {data.get('uptime_sec', 0)}s")
        print(f"  Packets:     {data.get('packets_captured', 0)}")
        print(f"  Flows:       {data.get('flows_active', 0)}")
        print(f"  Incidents:   {data.get('incidents_open', 0)}")
        print(f"  Rules:       {data.get('rules_loaded', 0)}")
        print(f"  Processed:   {data.get('pipeline_processed', 0)}")
        print(f"  Detections:  {data.get('pipeline_detections', 0)}")
        degraded = data.get("degraded", False)
        print(f"  Degraded:    {'YES' if degraded else 'no'}")
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    try:
        client = AegisClient()
        resp = client.send("health.check")
    except AegisCtlError as e:
        print(f"[!] AEGIS daemon not reachable: {e}", file=sys.stderr)
        return 2
    data = resp.get("data", {})
    if getattr(args, "json", False):
        print(json.dumps(data, indent=2))
    else:
        print(f"  Component:   {data.get('component', '?')}")
        print(f"  State:       {data.get('state', '?')}")
        print(f"  PID:         {data.get('pid', '?')}")
        print(f"  Uptime:      {data.get('uptime_ms', 0)}ms")
        print(f"  Degraded:    {'YES' if data.get('degraded') else 'no'}")
        checks = data.get("checks", [])
        if checks:
            print("  Checks:")
            for c in checks:
                status = "OK" if c.get("ok") else "FAIL"
                print(f"    {c.get('name', '?'):<12} {status:<6} {c.get('detail', '')}")
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    try:
        client = AegisClient()
        resp = client.send("version")
    except AegisCtlError:
        print("Component         Version")
        print("-" * 40)
        component = getattr(args, "component", None)
        if component:
            print(f"{component:<18}(daemon not reachable)")
        else:
            for comp in ["core", "nose", "shield", "pep", "brain", "bridge"]:
                print(f"{comp:<18}(daemon not reachable)")
        return 0
    data = resp.get("data", {})
    component = getattr(args, "component", None)
    print("Component         Version")
    print("-" * 40)
    if component:
        v = data.get(component, "unknown")
        print(f"{component:<18}v{v}")
    else:
        for comp, ver in data.items():
            print(f"{comp:<18}v{ver}")
    return 0


def cmd_diagnose(args: argparse.Namespace) -> int:
    print("AEGIS NIDS Diagnostic Report")
    print("=" * 60)
    print()
    print("VERSION")
    print("-" * 60)
    print(f"  CLI: aegisctl v6.0+")
    print(f"  Python: {platform.python_version()}")
    print(f"  Platform: {platform.platform()}")
    print(f"  Repo root: {REPO_ROOT}")
    print()
    try:
        client = AegisClient()
        status_resp = client.send("status")
        status_data = status_resp.get("data", {})
        print("RUNTIME STATUS")
        print("-" * 60)
        print(f"  State:       {status_data.get('state', '?')}")
        print(f"  Version:     {status_data.get('version', '?')}")
        print(f"  Uptime:      {status_data.get('uptime_sec', 0)}s")
        print(f"  Degraded:    {'YES' if status_data.get('degraded') else 'no'}")
        print(f"  Rules:       {status_data.get('rules_loaded', 0)}")
        print(f"  Packets:     {status_data.get('packets_captured', 0)}")
        print(f"  Incidents:   {status_data.get('incidents_open', 0)}")
    except AegisCtlError:
        print("RUNTIME STATUS")
        print("-" * 60)
        print("  (daemon not reachable)")
    print()
    try:
        health_resp = client.send("health.check")
        health_data = health_resp.get("data", {})
        checks = health_data.get("checks", [])
        print("SUBSYSTEM HEALTH")
        print("-" * 60)
        for c in checks:
            status = "OK" if c.get("ok") else "FAIL"
            print(f"  {c.get('name', '?'):<12} {status:<6} {c.get('detail', '')}")
    except AegisCtlError:
        print("SUBSYSTEM HEALTH")
        print("-" * 60)
        print("  (daemon not reachable)")
    print()
    print("LOG FILES")
    print("-" * 60)
    for name in ["aegis_core.ndjson", "aegis.log", "canary_results.json"]:
        path = LOGS_DIR / name
        if path.exists():
            size = path.stat().st_size
            print(f"  {name:<30} {size:>10} bytes")
        else:
            print(f"  {name:<30} {'(missing)':>10}")
    print()
    print("Diagnostic report complete")
    return 0


def register_commands() -> None:
    pass


def setup_subcommands(sub) -> None:
    p = sub.add_parser("status", help="Show daemon status")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("health", help="Health check")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("version", help="Show version")
    p.add_argument("--component")
    p.add_argument("--json", action="store_true")

    sub.add_parser("diagnose", help="Run diagnostics")
