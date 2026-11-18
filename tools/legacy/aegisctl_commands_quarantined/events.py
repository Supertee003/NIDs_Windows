"""Events management commands."""
from __future__ import annotations

# QUARANTINED (LEGACY-INERT-001): retained for history only.
# Nothing in the runtime imports this file and the installer does not ship it.
# Several of these scripts rewrite tracked files when run (for example
# tools/aegisctl/commands/console.py or AUTHORITY_MAP.json), so an accidental
# `python tools/legacy/<name>.py` was a tree mutation. The guard below makes the
# file inert: it exits before any line of the original body executes.
raise SystemExit(
    "QUARANTINED: tools/legacy/aegisctl_commands_quarantined/events.py must not run; retained for history only."
)

import argparse
import json
import sys
from typing import Dict

from ..utils import read_ndjson


def cmd_events_count(args: argparse.Namespace) -> int:
    entries = read_ndjson()
    print(f"Events: {len(entries)}")
    return 0


def cmd_events_tail(args: argparse.Namespace) -> int:
    count = getattr(args, "count", 10)
    entries = read_ndjson()
    if not entries:
        print("No events")
        return 0
    for e in entries[-count:]:
        print(json.dumps(e))
    print(f"{len(entries[-count:])} event(s)")
    return 0


def cmd_events_stats(args: argparse.Namespace) -> int:
    entries = read_ndjson()
    if not entries:
        print("No log file")
        return 0
    print("Event Statistics")
    print("-" * 40)
    types: Dict[str, int] = {}
    for e in entries:
        t = e.get("type", e.get("event_type", "unknown"))
        types[t] = types.get(t, 0) + 1
    for t, c in sorted(types.items()):
        print(f"  {t:<32} {c}")
    print(f"\nTotal: {len(entries)}")
    return 0


def register_commands() -> None:
    pass


def setup_subcommands(sub) -> None:
    p = sub.add_parser("events", help="Event management")
    ep = p.add_subparsers(dest="events_cmd")

    ep.add_parser("count", help="Count events")

    et = ep.add_parser("tail", help="Tail events")
    et.add_argument("--count", type=int, default=10)

    ep.add_parser("stats", help="Event statistics")
