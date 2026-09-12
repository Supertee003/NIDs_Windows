"""Intelligence commands (incidents, federation, metrics)."""
from __future__ import annotations

import argparse
import json
import sys

from ..client import AegisClient, AegisCtlError


def cmd_incidents(args: argparse.Namespace) -> int:
    try:
        client = AegisClient(transport=getattr(args, "transport", "pipe"))
        resp = client.send("incidents.list", {"severity_min": args.severity})
    except AegisCtlError as e:
        print(f"[!] AEGIS daemon not reachable: {e}", file=sys.stderr)
        return 2
    incs = resp.get("data", {}).get("incidents", [])
    if not incs:
        print("(no open incidents)")
        return 0
    for i in incs:
        print(f"#{i.get('id', 0):<6} sev={i.get('severity'):<8} score={i.get('score', 0):<6} src={i.get('src_ip'):<12}")
    return 0


def cmd_federation(args: argparse.Namespace) -> int:
    try:
        client = AegisClient(transport=getattr(args, "transport", "pipe"))
        resp = client.send("federation.status")
    except AegisCtlError as e:
        print(f"[!] AEGIS daemon not reachable: {e}", file=sys.stderr)
        return 2
    data = resp.get("data", {})
    print(f"Federation: {'enabled' if data.get('enabled') else 'disabled'}")
    return 0


def cmd_metrics(args: argparse.Namespace) -> int:
    try:
        client = AegisClient(transport=getattr(args, "transport", "pipe"))
        resp = client.send("metrics.snapshot")
    except AegisCtlError as e:
        print(f"[!] AEGIS daemon not reachable: {e}", file=sys.stderr)
        return 2
    data = resp.get("data", {})
    if getattr(args, "json", False):
        print(json.dumps(data, indent=2))
    else:
        for key, value in data.items():
            print(f"  {key:<32} {value}")
    return 0


def register_commands() -> None:
    pass


def setup_subcommands(sub) -> None:
    p = sub.add_parser("incidents", help="Incident management")
    p.add_argument("--severity", default="warning")

    sub.add_parser("federation", help="Federation status")

    p = sub.add_parser("metrics", help="Metrics snapshot")
    p.add_argument("--json", action="store_true")
