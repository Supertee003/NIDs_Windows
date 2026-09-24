"""Status, health, version, diagnose commands."""
from __future__ import annotations

import argparse
import json
import platform
import sys
from typing import Dict

from .. import (
    EXIT_OK, EXIT_FAILED, EXIT_RUNTIME_UNAVAILABLE,
    structured_error, structured_ok,
)
from ..client import AegisClient, AegisCtlError
from ..config import REPO_ROOT, LOGS_DIR


def cmd_status(args: argparse.Namespace) -> int:
    try:
        client = AegisClient(transport=getattr(args, "transport", "pipe"))
        resp = client.send("status")
    except AegisCtlError as e:
        err = structured_error(EXIT_RUNTIME_UNAVAILABLE, "RUNTIME_UNAVAILABLE", str(e), "UNKNOWN")
        if getattr(args, "json", False):
            print(json.dumps(err, indent=2))
        else:
            print(f"[!] AEGIS daemon not reachable: {e}", file=sys.stderr)
        return EXIT_RUNTIME_UNAVAILABLE
    data = resp.get("data", {})
    if getattr(args, "json", False):
        print(json.dumps(structured_ok(data, data.get("state", "OK")), indent=2))
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
    return EXIT_OK


def cmd_health(args: argparse.Namespace) -> int:
    try:
        client = AegisClient(transport=getattr(args, "transport", "pipe"))
        resp = client.send("health.check")
    except AegisCtlError as e:
        err = structured_error(EXIT_RUNTIME_UNAVAILABLE, "RUNTIME_UNAVAILABLE", str(e), "UNKNOWN")
        if getattr(args, "json", False):
            print(json.dumps(err, indent=2))
        else:
            print(f"[!] AEGIS daemon not reachable: {e}", file=sys.stderr)
        return EXIT_RUNTIME_UNAVAILABLE
    data = resp.get("data", {})
    if getattr(args, "json", False):
        print(json.dumps(structured_ok(data, data.get("state", "OK")), indent=2))
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
    return EXIT_OK


def cmd_version(args: argparse.Namespace) -> int:
    try:
        client = AegisClient(transport=getattr(args, "transport", "pipe"))
        resp = client.send("version")
    except AegisCtlError as e:
        err = structured_error(EXIT_RUNTIME_UNAVAILABLE, "RUNTIME_UNAVAILABLE", str(e), "UNKNOWN")
        if getattr(args, "json", False):
            print(json.dumps(err, indent=2))
        else:
            print(f"[!] AEGIS daemon not reachable: {e}", file=sys.stderr)
        return EXIT_RUNTIME_UNAVAILABLE
    data = resp.get("data", {})
    component = getattr(args, "component", None)
    if getattr(args, "json", False):
        print(json.dumps(structured_ok(data), indent=2))
    else:
        print("Component         Version")
        print("-" * 40)
        if component:
            v = data.get(component, "unknown")
            print(f"{component:<18}v{v}")
        else:
            for comp, ver in data.items():
                print(f"{comp:<18}v{ver}")
    return EXIT_OK


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
    daemon_ok = True
    try:
        client = AegisClient(transport=getattr(args, "transport", "pipe"))
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
        daemon_ok = False
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
    return EXIT_OK if daemon_ok else EXIT_RUNTIME_UNAVAILABLE


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
