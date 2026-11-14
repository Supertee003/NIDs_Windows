"""Log management commands."""
from __future__ import annotations

# QUARANTINED (LEGACY-INERT-001): retained for history only.
# Nothing in the runtime imports this file and the installer does not ship it.
# Several of these scripts rewrite tracked files when run (for example
# tools/aegisctl/commands/console.py or AUTHORITY_MAP.json), so an accidental
# `python tools/legacy/<name>.py` was a tree mutation. The guard below makes the
# file inert: it exits before any line of the original body executes.
raise SystemExit(
    "QUARANTINED: tools/legacy/aegisctl_commands_quarantined/logs.py must not run; retained for history only."
)

import argparse
import sys
import time
from pathlib import Path

from ..config import LOGS_DIR


def cmd_logs_tail(args: argparse.Namespace) -> int:
    log_path = LOGS_DIR / "aegis.log"
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


def register_commands() -> None:
    pass


def setup_subcommands(sub) -> None:
    p = sub.add_parser("logs", help="Log management")
    lp = p.add_subparsers(dest="log_cmd")
    lp.add_parser("tail", help="Tail logs")
