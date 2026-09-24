"""Block, quarantine, enforce commands."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Dict

from ..config import BLOCKED_IPS_FILE, QUARANTINE_FILE, PEP_STATE_FILE, RULES_FILE, ROLE_OPERATE, ROLE_PRIVILEGED
from ..utils import load_json, save_json, control_request


def cmd_block_add(args: argparse.Namespace) -> int:
    control_request("block_request", ROLE_OPERATE, ip=args.ip)
    data = load_json(BLOCKED_IPS_FILE) or {"blocked_ips": []}
    blocked = data.get("blocked_ips", [])
    ip = args.ip
    reason = getattr(args, "reason", "manual block")
    duration = getattr(args, "duration", None)
    for entry in blocked:
        if entry.get("ip") == ip:
            print(f"IP {ip} already BLOCKED")
            return 0
    entry = {"ip": ip, "reason": reason}
    if duration:
        entry["duration"] = duration
        print(f"IP {ip} BLOCKED for {duration}s")
    else:
        print(f"IP {ip} BLOCKED")
    blocked.append(entry)
    data["blocked_ips"] = blocked
    save_json(BLOCKED_IPS_FILE, data)
    return 0


def cmd_block_remove(args: argparse.Namespace) -> int:
    data = load_json(BLOCKED_IPS_FILE) or {"blocked_ips": []}
    blocked = data.get("blocked_ips", [])
    ip = args.ip
    new_blocked = [e for e in blocked if e.get("ip") != ip]
    if len(new_blocked) == len(blocked):
        print(f"IP {ip} NOT in the block list")
        return 0
    data["blocked_ips"] = new_blocked
    save_json(BLOCKED_IPS_FILE, data)
    print(f"IP {ip} UNBLOCKED")
    return 0


def cmd_block_list(args: argparse.Namespace) -> int:
    data = load_json(BLOCKED_IPS_FILE) or {"blocked_ips": []}
    blocked = data.get("blocked_ips", [])
    if not blocked:
        print("No IPs in block list")
        return 0
    print(f"{'IP':<20} {'Reason':<30}")
    print("-" * 52)
    for entry in blocked:
        print(f"{entry.get('ip', '?'):<20} {entry.get('reason', '?'):<30}")
    print(f"\nTotal: {len(blocked)}")
    return 0


def cmd_block_clear(args: argparse.Namespace) -> int:
    data = load_json(BLOCKED_IPS_FILE) or {"blocked_ips": []}
    count = len(data.get("blocked_ips", []))
    if count == 0:
        print("Block list already empty")
        return 0
    save_json(BLOCKED_IPS_FILE, {"blocked_ips": []})
    print(f"Cleared {count} IPs from block list")
    return 0


def cmd_quarantine_add(args: argparse.Namespace) -> int:
    data = load_json(QUARANTINE_FILE) or {"quarantined_ips": []}
    quarantined = data.get("quarantined_ips", [])
    ip = args.ip
    reason = getattr(args, "reason", "quarantine")
    for entry in quarantined:
        if entry.get("ip") == ip:
            print(f"IP {ip} already QUARANTINED")
            return 0
    quarantined.append({"ip": ip, "reason": reason})
    data["quarantined_ips"] = quarantined
    save_json(QUARANTINE_FILE, data)
    print(f"IP {ip} QUARANTINED")
    # Also add to block list
    block_data = load_json(BLOCKED_IPS_FILE) or {"blocked_ips": []}
    blocked = block_data.get("blocked_ips", [])
    for entry in blocked:
        if entry.get("ip") == ip:
            break
    else:
        blocked.append({"ip": ip, "reason": f"QUARANTINE - {reason}"})
        block_data["blocked_ips"] = blocked
        save_json(BLOCKED_IPS_FILE, block_data)
    return 0


def cmd_quarantine_remove(args: argparse.Namespace) -> int:
    data = load_json(QUARANTINE_FILE) or {"quarantined_ips": []}
    quarantined = data.get("quarantined_ips", [])
    ip = args.ip
    new_q = [e for e in quarantined if e.get("ip") != ip]
    if len(new_q) == len(quarantined):
        print(f"IP {ip} NOT in the quarantine")
        return 0
    data["quarantined_ips"] = new_q
    save_json(QUARANTINE_FILE, data)
    # Also remove from block list
    block_data = load_json(BLOCKED_IPS_FILE) or {"blocked_ips": []}
    blocked = block_data.get("blocked_ips", [])
    block_data["blocked_ips"] = [e for e in blocked if e.get("ip") != ip]
    save_json(BLOCKED_IPS_FILE, block_data)
    print(f"IP {ip} removed from quarantine")
    return 0


def cmd_quarantine_list(args: argparse.Namespace) -> int:
    data = load_json(QUARANTINE_FILE) or {"quarantined_ips": []}
    quarantined = data.get("quarantined_ips", [])
    if not quarantined:
        print("No IPs in quarantine")
        return 0
    print(f"{'IP':<20} {'Reason':<30}")
    print("-" * 52)
    for entry in quarantined:
        print(f"{entry.get('ip', '?'):<20} {entry.get('reason', '?'):<30}")
    print(f"\nTotal: {len(quarantined)}")
    return 0


def cmd_enforce_status(args: argparse.Namespace) -> int:
    data = load_json(PEP_STATE_FILE) or {}
    enabled = data.get("enabled", True)
    mode = data.get("mode", "enforce")
    print("PEP Enforcement Status")
    print("-" * 40)
    print(f"  Enabled: {'true' if enabled else 'false'}")
    print(f"  Mode:    {mode}")
    return 0


def cmd_enforce_enable(args: argparse.Namespace) -> int:
    data = load_json(PEP_STATE_FILE) or {}
    if data.get("enabled", True):
        print("PEP already ENABLED")
        return 0
    data["enabled"] = True
    data["mode"] = "enforce"
    save_json(PEP_STATE_FILE, data)
    print("PEP ENABLED")
    return 0


def cmd_enforce_disable(args: argparse.Namespace) -> int:
    data = load_json(PEP_STATE_FILE) or {"enabled": True}
    if not data.get("enabled", True):
        print("PEP already DISABLED")
        return 0
    data["enabled"] = False
    data["mode"] = "monitor"
    save_json(PEP_STATE_FILE, data)
    print("PEP DISABLED")
    return 0


def cmd_enforce_push(args: argparse.Namespace) -> int:
    control_request("enforce_push", ROLE_PRIVILEGED, policy_file=args.policy)
    from pathlib import Path
    policy_file = Path(args.policy)
    if not policy_file.exists():
        print(f"ERROR: file not found: {policy_file}")
        return 1
    try:
        content = policy_file.read_text(encoding="utf-8")
        policy_data = json.loads(content)
    except json.JSONDecodeError:
        print(f"ERROR: invalid json in {policy_file}")
        return 1
    rules = policy_data if isinstance(policy_data, list) else policy_data.get("rules", policy_data.get("nids_rules", []))
    RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(policy_data, dict):
        RULES_FILE.write_text(json.dumps(policy_data, indent=2), encoding="utf-8")
    else:
        RULES_FILE.write_text(json.dumps({"rules": rules}, indent=2), encoding="utf-8")
    print(f"Policy pushed successfully")
    print(f"Rules: {len(rules)}")
    return 0


def register_commands() -> None:
    pass


def setup_subcommands(sub) -> None:
    p = sub.add_parser("block", help="IP block management")
    bp = p.add_subparsers(dest="block_cmd")

    ba = bp.add_parser("add", help="Block IP")
    ba.add_argument("--ip", required=True)
    ba.add_argument("--reason", default="manual block")
    ba.add_argument("--duration", type=int)

    br = bp.add_parser("remove", help="Unblock IP")
    br.add_argument("--ip", required=True)

    bp.add_parser("list", help="List blocked IPs")
    bp.add_parser("clear", help="Clear block list")

    p = sub.add_parser("quarantine", help="Quarantine management")
    qp = p.add_subparsers(dest="quarantine_cmd")

    qa = qp.add_parser("add", help="Quarantine IP")
    qa.add_argument("--ip", required=True)
    qa.add_argument("--reason", default="quarantine")

    qr = qp.add_parser("remove", help="Remove from quarantine")
    qr.add_argument("--ip", required=True)

    qp.add_parser("list", help="List quarantined IPs")

    p = sub.add_parser("enforce", help="Enforcement management")
    ep = p.add_subparsers(dest="enforce_cmd")

    ep.add_parser("status", help="Enforcement status")
    ep.add_parser("enable", help="Enable enforcement")
    ep.add_parser("disable", help="Disable enforcement")

    epp = ep.add_parser("push", help="Push policy")
    epp.add_argument("--policy", required=True)
