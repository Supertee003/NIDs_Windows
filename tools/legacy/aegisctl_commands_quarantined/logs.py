"""Log management commands."""
from __future__ import annotations

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
