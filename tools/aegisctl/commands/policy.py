"""Policy management commands."""
from __future__ import annotations

import argparse
import json
import sys

from ..utils import load_rules, load_disabled_rules, save_disabled_rules


def cmd_policy_list(args: argparse.Namespace) -> int:
    rules = load_rules()
    disabled = load_disabled_rules()
    print(f"{'Rule ID':<12} {'State':<12}")
    print("-" * 26)
    for r in rules:
        rid = str(r.get("id", r.get("rule_id", "?")))
        state = "DISABLED" if rid in disabled else "ENABLED"
        print(f"{rid:<12} {state:<12}")
    print(f"\nTotal: {len(rules)}")
    return 0


def cmd_policy_show(args: argparse.Namespace) -> int:
    rules = load_rules()
    disabled = load_disabled_rules()
    for r in rules:
        rid = str(r.get("rule_id", r.get("id", "")))
        if rid == str(args.id):
            r["state"] = "DISABLED" if rid in disabled else "ENABLED"
            print(json.dumps(r, indent=2))
            return 0
    print(f"Rule {args.id} not found")
    return 1


def cmd_policy_disable(args: argparse.Namespace) -> int:
    rules = load_rules()
    found = any(str(r.get("rule_id", r.get("id", ""))) == args.id for r in rules)
    if not found:
        print(f"Rule {args.id} not found")
        return 1
    disabled = load_disabled_rules()
    if args.id in disabled:
        print(f"Rule {args.id} already DISABLED")
        return 0
    disabled.append(args.id)
    save_disabled_rules(disabled)
    print(f"Rule {args.id} DISABLED")
    return 0


def cmd_policy_enable(args: argparse.Namespace) -> int:
    rules = load_rules()
    found = any(str(r.get("rule_id", r.get("id", ""))) == args.id for r in rules)
    if not found:
        print(f"Rule {args.id} not found")
        return 1
    disabled = load_disabled_rules()
    if args.id not in disabled:
        print(f"Rule {args.id} already ENABLED")
        return 0
    disabled.remove(args.id)
    save_disabled_rules(disabled)
    print(f"Rule {args.id} ENABLED")
    return 0


def cmd_policy_reload(args: argparse.Namespace) -> int:
    try:
        from ..client import AegisClient
        client = AegisClient()
        resp = client.send("rules.reload")
        if resp.get("ok"):
            print("[OK]  Policy reloaded")
            return 0
    except Exception:
        pass
    print("ERROR: not running")
    return 1


def register_commands() -> None:
    pass


def setup_subcommands(sub) -> None:
    p = sub.add_parser("policy", help="Policy management")
    pp = p.add_subparsers(dest="policy_cmd")

    pp.add_parser("list", help="List policies")

    ps = pp.add_parser("show", help="Show policy")
    ps.add_argument("--id", required=True)

    pd = pp.add_parser("disable", help="Disable policy")
    pd.add_argument("--id", required=True)

    pe = pp.add_parser("enable", help="Enable policy")
    pe.add_argument("--id", required=True)

    pp.add_parser("reload", help="Reload policies")
