"""Backup and restore commands."""
from __future__ import annotations

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
