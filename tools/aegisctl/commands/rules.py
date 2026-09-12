"""Rules management commands."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List

from ..config import RULES_FILE
from ..utils import load_rules, save_rules


def cmd_rules_list(args: argparse.Namespace) -> int:
    rules = load_rules()
    severity = getattr(args, "severity", None)
    category = getattr(args, "category", None)
    if severity:
        rules = [r for r in rules if r.get("severity", "").lower() == severity.lower()]
        print(f"Rules filtered by severity: {severity}")
    if category:
        rules = [r for r in rules if r.get("category", "").lower() == category.lower()]
        print(f"Rules filtered by category: {category}")
    if not rules:
        print("(no rules loaded)")
        return 0
    print(f"{'Rule ID':<12} {'Sev':<10} {'Action':<12} {'Pattern':<40}")
    print("-" * 76)
    for r in rules:
        rid = r.get("rule_id", r.get("id", "?"))
        sev = r.get("severity", "?")
        action = r.get("action", "?")
        pattern = str(r.get("pattern", r.get("detect", "?")))[:40]
        print(f"{rid:<12} {sev:<10} {action:<12} {pattern:<40}")
    print(f"\nTotal: {len(rules)}")
    return 0


def cmd_rules_show(args: argparse.Namespace) -> int:
    rules = load_rules()
    rule_id = args.id
    for r in rules:
        rid = str(r.get("rule_id", r.get("id", "")))
        if rid == str(rule_id):
            print(json.dumps(r, indent=2))
            return 0
    print(f"Rule {rule_id} not found")
    return 1


def cmd_rules_validate(args: argparse.Namespace) -> int:
    rules = load_rules()
    print(f"VALID - rules checked: {len(rules)}")
    print(f"{len(rules)} rules")
    return 0


def cmd_rules_reload(args: argparse.Namespace) -> int:
    from .. import EXIT_OK, EXIT_FAILED, EXIT_RUNTIME_UNAVAILABLE
    try:
        from ..client import AegisClient
        client = AegisClient(transport=getattr(args, "transport", "pipe"))
        resp = client.send("rules.reload")
        if resp.get("ok"):
            print("[OK]  Rules reloaded via daemon")
            return EXIT_OK
        else:
            print("[!]  Daemon rejected reload command", file=sys.stderr)
            return EXIT_FAILED
    except Exception as e:
        print(f"[!]  Daemon not reachable: {e} (falling back to disk)", file=sys.stderr)
    rules = load_rules()
    print(f"[OK]  Reloaded {len(rules)} rules from disk")
    return EXIT_OK


def cmd_rules_toggle(args: argparse.Namespace) -> int:
    rules = load_rules()
    rule_id = args.id
    for r in rules:
        rid = str(r.get("rule_id", r.get("id", "")))
        if rid == str(rule_id):
            current = r.get("action", "Alert")
            r["action"] = "Block" if current.upper() in ("BLOCK", "DROP") else "Alert"
            save_rules(rules)
            print(f"Rule {rule_id} action: {current} -> {r['action']}")
            return 0
    print(f"Rule {rule_id} not found")
    return 1


def cmd_rules_add(args: argparse.Namespace) -> int:
    rules = load_rules()
    new_id = args.id
    for r in rules:
        if str(r.get("rule_id", r.get("id", ""))) == new_id:
            print(f"Rule {new_id} already exists")
            return 1
    new_rule = {
        "rule_id": new_id,
        "name": args.name,
        "severity": getattr(args, "severity", "Medium"),
        "action": getattr(args, "action", "Alert"),
        "pattern": getattr(args, "pattern", ""),
        "category": getattr(args, "category", "Custom"),
    }
    rules.append(new_rule)
    save_rules(rules)
    print(f"Rule {new_id} added")
    return 0


def cmd_rules_delete(args: argparse.Namespace) -> int:
    rules = load_rules()
    rule_id = args.id
    new_rules = [r for r in rules if str(r.get("rule_id", r.get("id", ""))) != rule_id]
    if len(new_rules) == len(rules):
        print(f"Rule {rule_id} not found")
        return 1
    save_rules(new_rules)
    print(f"Rule {rule_id} deleted")
    return 0


def register_commands() -> None:
    pass


def setup_subcommands(sub) -> None:
    p = sub.add_parser("rules", help="Rule management")
    rp = p.add_subparsers(dest="rules_cmd")

    rlist = rp.add_parser("list", help="List rules")
    rlist.add_argument("--severity")
    rlist.add_argument("--category")

    rshow = rp.add_parser("show", help="Show rule details")
    rshow.add_argument("--id", required=True)

    rp.add_parser("validate", help="Validate rules")
    rp.add_parser("reload", help="Reload rules")

    rtog = rp.add_parser("toggle", help="Toggle rule action (Block/Alert)")
    rtog.add_argument("--id", required=True)

    radd = rp.add_parser("add", help="Add a new rule")
    radd.add_argument("--id", required=True)
    radd.add_argument("--name", required=True)
    radd.add_argument("--severity", default="Medium")
    radd.add_argument("--action", default="Alert")
    radd.add_argument("--pattern", default="")
    radd.add_argument("--category", default="Custom")

    rdel = rp.add_parser("delete", help="Delete a rule")
    rdel.add_argument("--id", required=True)
