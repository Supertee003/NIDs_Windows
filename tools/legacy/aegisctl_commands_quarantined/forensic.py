"""Forensic record commands."""
from __future__ import annotations

# QUARANTINED (LEGACY-INERT-001): retained for history only.
# Nothing in the runtime imports this file and the installer does not ship it.
# Several of these scripts rewrite tracked files when run (for example
# tools/aegisctl/commands/console.py or AUTHORITY_MAP.json), so an accidental
# `python tools/legacy/<name>.py` was a tree mutation. The guard below makes the
# file inert: it exits before any line of the original body executes.
raise SystemExit(
    "QUARANTINED: tools/legacy/aegisctl_commands_quarantined/forensic.py must not run; retained for history only."
)

import argparse
import json
import sys
from pathlib import Path

from ..config import NDJSON_LOG
from ..utils import read_ndjson


def cmd_forensic_show(args: argparse.Namespace) -> int:
    entries = read_ndjson()
    for e in entries:
        if str(e.get("id", e.get("event_id", ""))) == str(args.id):
            print(json.dumps(e, indent=2))
            return 0
    print(f"Forensic record {args.id} not found", file=sys.stderr)
    return 1


def cmd_forensic_search(args: argparse.Namespace) -> int:
    if not NDJSON_LOG.exists():
        print("No log file")
        return 1
    entries = read_ndjson()
    found = [e for e in entries if str(e.get(args.field, "")) == args.value]
    for e in found:
        print(json.dumps(e))
    return 0


def cmd_forensic_export(args: argparse.Namespace) -> int:
    if not NDJSON_LOG.exists():
        print("No log file")
        return 1
    entries = read_ndjson()
    Path(args.output).write_text(json.dumps(entries, indent=2), encoding="utf-8")
    print(f"Exported {len(entries)} records to {args.output}")
    return 0


def register_commands() -> None:
    pass


def setup_subcommands(sub) -> None:
    p = sub.add_parser("forensic", help="Forensic records")
    fp = p.add_subparsers(dest="forensic_cmd")

    fs = fp.add_parser("show", help="Show forensic record")
    fs.add_argument("--id", required=True)

    fsr = fp.add_parser("search", help="Search forensic records")
    fsr.add_argument("--field", required=True)
    fsr.add_argument("--value", required=True)

    fse = fp.add_parser("export", help="Export forensic records")
    fse.add_argument("--output", required=True)
