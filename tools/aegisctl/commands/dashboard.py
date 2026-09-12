"""Live dashboard command."""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from ..config import REPO_ROOT, ANOMALOUS_LOG, RULES_FILE


def cmd_dashboard(args: argparse.Namespace) -> int:
    try:
        import psutil
    except ImportError:
        print("ERROR: psutil required for dashboard")
        return 1

    interval = getattr(args, "interval", 2)
    print("AEGIS NIDS Live Dashboard (Ctrl+C to exit)")
    print()

    try:
        while True:
            os.system("cls" if os.name == "nt" else "clear")

            cpu = psutil.cpu_percent(interval=0)
            mem = psutil.virtual_memory()

            rules = []
            if RULES_FILE.exists():
                try:
                    data = json.loads(RULES_FILE.read_text(encoding="utf-8"))
                    rules = data.get("nids_rules", data) if isinstance(data, dict) else data
                except Exception:
                    pass

            alerts = 0
            blocks = 0
            if ANOMALOUS_LOG.exists():
                try:
                    lines = ANOMALOUS_LOG.read_text(encoding="utf-8").splitlines()
                    alerts = len(lines)
                    blocks = sum(1 for l in lines if '"policy": "Block"' in l or '"policy": "Drop"' in l)
                except Exception:
                    pass

            print(f"{'=' * 60}")
            print(f"  AEGIS NIDS Dashboard")
            print(f"{'=' * 60}")
            print(f"  CPU: {cpu:.1f}%   Memory: {mem.percent:.1f}% ({mem.used / 1024**3:.1f}GB / {mem.total / 1024**3:.1f}GB)")
            print(f"  Rules: {len(rules)}   Alerts: {alerts}   Blocks: {blocks}")
            print(f"{'=' * 60}")
            print()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nDashboard stopped")
        return 0


def register_commands() -> None:
    pass


def setup_subcommands(sub) -> None:
    p = sub.add_parser("dashboard", help="Live dashboard")
    p.add_argument("--interval", type=int, default=2, help="Refresh interval (seconds)")
