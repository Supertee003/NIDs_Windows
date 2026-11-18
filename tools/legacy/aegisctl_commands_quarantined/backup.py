"""Backup and restore commands."""
from __future__ import annotations

# QUARANTINED (LEGACY-INERT-001): retained for history only.
# Nothing in the runtime imports this file and the installer does not ship it.
# Several of these scripts rewrite tracked files when run (for example
# tools/aegisctl/commands/console.py or AUTHORITY_MAP.json), so an accidental
# `python tools/legacy/<name>.py` was a tree mutation. The guard below makes the
# file inert: it exits before any line of the original body executes.
raise SystemExit(
    "QUARANTINED: tools/legacy/aegisctl_commands_quarantined/backup.py must not run; retained for history only."
)

import argparse


def cmd_backup(args: argparse.Namespace) -> int:
    print(f"[OK]  Backup created")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    print(f"[OK]  Restore complete")
    return 0


def register_commands() -> None:
    pass


def setup_subcommands(sub) -> None:
    p = sub.add_parser("backup", help="Backup state")
    p.add_argument("--output", default="aegis_backup.zip")

    p = sub.add_parser("restore", help="Restore state")
    p.add_argument("--input", required=True)
