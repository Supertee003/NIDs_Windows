"""Alert viewer and acknowledgement commands."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from ..config import REPO_ROOT, NDJSON_LOG

ACK_FILE = REPO_ROOT / "logs" / "acknowledged_alerts.json"


def _load_acked() -> set:
    if ACK_FILE.exists():
        try:
            return set(json.loads(ACK_FILE.read_text(encoding="utf-8")))
        except Exception:
            pass
    return set()


def _save_acked(acked: set) -> None:
    ACK_FILE.parent.mkdir(parents=True, exist_ok=True)
    ACK_FILE.write_text(json.dumps(sorted(acked)), encoding="utf-8")


def cmd_alerts_view(args: argparse.Namespace) -> int:
    if not NDJSON_LOG.exists():
        print("No alert log found")
        return 1
    lines = NDJSON_LOG.read_text(encoding="utf-8").splitlines()
    acked = _load_acked()
    entries = []
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            entry["_line"] = i
            entries.append(entry)
        except json.JSONDecodeError:
            pass

    show_all = getattr(args, "all", False)
    unacked_only = getattr(args, "unacked", False)
    filter_type = getattr(args, "filter", None)

    if not show_all:
        entries = entries[-50:]

    if unacked_only:
        entries = [e for e in entries if str(e.get("_line", "")) not in acked]

    if filter_type:
        entries = [e for e in entries if filter_type.upper() in json.dumps(e).upper()]

    if not entries:
        print("No alerts found")
        return 0

    for e in entries:
        line_num = e.get("_line", "?")
        ts = e.get("timestamp", "?")
        attack = e.get("attack_type", e.get("type", "Unknown"))
        policy = e.get("policy", "ALERT").upper()
        source = e.get("source", e.get("src_ip", "?"))
        acked_marker = " [ACKED]" if str(line_num) in acked else ""
        print(f"  #{line_num:<6} [{ts}] {source:<16} {attack:<24} {policy}{acked_marker}")

    print(f"\nShowing {len(entries)} alerts")
    return 0


def cmd_alerts_ack(args: argparse.Namespace) -> int:
    acked = _load_acked()
    acked.add(str(args.id))
    _save_acked(acked)
    print(f"Alert #{args.id} acknowledged")
    return 0


def register_commands() -> None:
    pass


def setup_subcommands(sub) -> None:
    p = sub.add_parser("alerts", help="Alert viewer & acknowledgement")
    ap = p.add_subparsers(dest="alerts_cmd")

    av = ap.add_parser("view", help="View alerts")
    av.add_argument("--all", action="store_true")
    av.add_argument("--unacked", action="store_true")
    av.add_argument("--filter")

    aack = ap.add_parser("ack", help="Acknowledge alert")
    aack.add_argument("--id", required=True)
