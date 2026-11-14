"""Go aggregator API client commands."""
from __future__ import annotations

# QUARANTINED (LEGACY-INERT-001): retained for history only.
# Nothing in the runtime imports this file and the installer does not ship it.
# Several of these scripts rewrite tracked files when run (for example
# tools/aegisctl/commands/console.py or AUTHORITY_MAP.json), so an accidental
# `python tools/legacy/<name>.py` was a tree mutation. The guard below makes the
# file inert: it exits before any line of the original body executes.
raise SystemExit(
    "QUARANTINED: tools/legacy/aegisctl_commands_quarantined/api.py must not run; retained for history only."
)

import argparse
import json
import sys

from ..client import AegisAPI


def cmd_api_health(args: argparse.Namespace) -> int:
    api = AegisAPI()
    if api.is_available():
        print("Aggregator: HEALTHY")
        return 0
    print("Aggregator: UNREACHABLE", file=sys.stderr)
    return 1


def cmd_api_alerts(args: argparse.Namespace) -> int:
    api = AegisAPI()
    alerts = api.get_alerts()
    if not alerts:
        print("No alerts")
        return 0
    for a in alerts:
        print(json.dumps(a))
    print(f"\nTotal: {len(alerts)}")
    return 0


def cmd_api_stats(args: argparse.Namespace) -> int:
    api = AegisAPI()
    stats = api.get_stats()
    if not stats:
        print("No stats available")
        return 0
    for k, v in stats.items():
        print(f"  {k:<32} {v}")
    return 0


def register_commands() -> None:
    pass


def setup_subcommands(sub) -> None:
    p = sub.add_parser("api", help="Go aggregator API")
    ap = p.add_subparsers(dest="api_cmd")

    ap.add_parser("health", help="Check aggregator health")
    ap.add_parser("alerts", help="Get alerts from aggregator")
    ap.add_parser("stats", help="Get stats from aggregator")
