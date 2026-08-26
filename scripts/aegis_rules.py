#!/usr/bin/env python3
"""
aegis_rules.py - AEGIS NIDS Rule Management CLI (Phase 16, UX-09)

Lists, inspects, and manages detection rules from config/Rules.json.
Supports viewing rule details, match counts, and toggling rules.

Usage:
  python aegis_rules.py                    # List all rules
  python aegis_rules.py --detail <name>    # Show detailed rule info
  python aegis_rules.py --stats             # Show rule match statistics
  python aegis_rules.py --validate          # Validate rule file syntax
  python aegis_rules.py --reload            # Trigger hot-reload (touches Rules.json)
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

AEGIS_ROOT = Path(__file__).parent.parent
RULES_FILE = AEGIS_ROOT / "config" / "Rules.json"
LOG_FILE = AEGIS_ROOT / "logs" / "aegis_core.ndjson"


def load_rules():
    """Load rules from Rules.json."""
    if not RULES_FILE.exists():
        print(f"[ERROR] Rules file not found: {RULES_FILE}", file=sys.stderr)
        return None
    try:
        data = json.loads(RULES_FILE.read_text(encoding='utf-8'))
        return data.get('nids_rules', [])
    except (json.JSONDecodeError, OSError) as e:
        print(f"[ERROR] Failed to load rules: {e}", file=sys.stderr)
        return None


def list_rules():
    """List all rules in a formatted table."""
    rules = load_rules()
    if rules is None:
        return 1

    print("=" * 90)
    print(f"  AEGIS NIDS Detection Rules ({len(rules)} rules)")
    print("=" * 90)
    print(f"{'#':>3}  {'Name':<30}  {'Severity':<10}  {'Action':<8}  {'Fast Pattern':<30}")
    print("-" * 90)

    for i, rule in enumerate(rules, 1):
        name = rule.get('name', '?')[:30]
        severity = rule.get('severity', '?')[:10]
        action = rule.get('action', '?')[:8]
        fast_pattern = rule.get('fast_pattern', rule.get('match_pattern', ''))[:30]
        print(f"{i:>3}  {name:<30}  {severity:<10}  {action:<8}  {fast_pattern:<30}")

    print("=" * 90)
    return 0


def show_detail(name: str):
    """Show detailed information about a specific rule."""
    rules = load_rules()
    if rules is None:
        return 1

    for rule in rules:
        if rule.get('name') == name:
            print(json.dumps(rule, indent=2))
            return 0

    print(f"[ERROR] Rule '{name}' not found", file=sys.stderr)
    return 1


def show_stats():
    """Show rule match statistics from forensic log."""
    rules = load_rules()
    if rules is None:
        return 1

    # Count matches from forensic log
    match_counts = {}
    if LOG_FILE.exists():
        try:
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        if event.get('event') in ('MATCH', 'BLOCK'):
                            rule_name = event.get('rule', '')
                            if rule_name:
                                match_counts[rule_name] = match_counts.get(rule_name, 0) + 1
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass

    print("=" * 80)
    print("  AEGIS NIDS Rule Match Statistics")
    print("=" * 80)
    print(f"{'Rule':<30}  {'Severity':<10}  {'Action':<8}  {'Matches':>8}")
    print("-" * 80)

    for rule in rules:
        name = rule.get('name', '?')[:30]
        severity = rule.get('severity', '?')[:10]
        action = rule.get('action', '?')[:8]
        matches = match_counts.get(name, 0)
        print(f"{name:<30}  {severity:<10}  {action:<8}  {matches:>8}")

    print("=" * 80)
    total = sum(match_counts.values())
    print(f"  Total matches: {total}")
    return 0


def validate_rules():
    """Validate rule file syntax."""
    rules = load_rules()
    if rules is None:
        return 1

    errors = []
    for i, rule in enumerate(rules, 1):
        if not rule.get('name'):
            errors.append(f"Rule #{i}: missing 'name' field")
        if not rule.get('fast_pattern') and not rule.get('match_pattern'):
            errors.append(f"Rule '{rule.get('name', '#'+str(i))}': missing both fast_pattern and match_pattern")
        sev = rule.get('severity', '')
        if sev and sev not in ('Critical', 'High', 'Medium', 'Low', 'Alert'):
            errors.append(f"Rule '{rule['name']}': unknown severity '{sev}'")
        act = rule.get('action', '')
        if act and act not in ('Block', 'Alert', 'Log'):
            errors.append(f"Rule '{rule['name']}': unknown action '{act}'")

    if errors:
        print(f"[FAIL] {len(errors)} validation errors:")
        for err in errors:
            print(f"  - {err}")
        return 1
    else:
        print(f"[OK] All {len(rules)} rules validated successfully.")
        return 0


def trigger_reload():
    """Trigger hot-reload by touching Rules.json mtime."""
    if not RULES_FILE.exists():
        print(f"[ERROR] Rules file not found: {RULES_FILE}", file=sys.stderr)
        return 1
    # Touch the file to update mtime (watchdog will detect change)
    os.utime(str(RULES_FILE), None)
    print(f"[OK] Rules.json mtime updated - watchdog will trigger reload within 5s")
    return 0


# ============================================================
# OPS-2: HMAC-SHA256 tamper-evidence generator (IR-13)
# ============================================================

def generate_hmac():
    """Generate HMAC-SHA256 of Rules.json and write to Rules.json.hmac."""
    import hashlib
    import hmac as hmac_module

    if not RULES_FILE.exists():
        print(f"[ERROR] Rules file not found: {RULES_FILE}", file=sys.stderr)
        return 1

    # Read HMAC key from env or use default
    hmac_key = os.getenv("AEGIS_RULES_HMAC_KEY", "AEGIS_NIDS_INTEGRITY_KEY_v1")
    if not os.getenv("AEGIS_RULES_HMAC_KEY"):
        print("[WARN] Using default HMAC key (set AEGIS_RULES_HMAC_KEY env var for production)", file=sys.stderr)

    # Read Rules.json content
    content = RULES_FILE.read_bytes()

    # Compute HMAC-SHA256
    hmac_obj = hmac_module.new(hmac_key.encode('utf-8'), content, hashlib.sha256)
    hmac_hex = hmac_obj.hexdigest()

    # Write to Rules.json.hmac
    hmac_file = RULES_FILE.parent / "Rules.json.hmac"
    hmac_file.write_text(hmac_hex)

    print(f"[OK] HMAC-SHA256 generated: {hmac_hex[:16]}...")
    print(f"     Written to: {hmac_file}")
    print(f"     Key source: {'env var' if os.getenv('AEGIS_RULES_HMAC_KEY') else 'default'}")
    return 0


def verify_hmac():
    """Verify HMAC-SHA256 of Rules.json against Rules.json.hmac."""
    import hashlib
    import hmac as hmac_module

    if not RULES_FILE.exists():
        print(f"[ERROR] Rules file not found: {RULES_FILE}", file=sys.stderr)
        return 1

    hmac_file = RULES_FILE.parent / "Rules.json.hmac"
    if not hmac_file.exists():
        print(f"[ERROR] HMAC file not found: {hmac_file}", file=sys.stderr)
        print("       Run: python aegis_rules.py --sign", file=sys.stderr)
        return 1

    hmac_key = os.getenv("AEGIS_RULES_HMAC_KEY", "AEGIS_NIDS_INTEGRITY_KEY_v1")
    content = RULES_FILE.read_bytes()
    stored_hmac = hmac_file.read_text().strip()

    # Compute HMAC-SHA256
    hmac_obj = hmac_module.new(hmac_key.encode('utf-8'), content, hashlib.sha256)
    computed_hmac = hmac_obj.hexdigest()

    if stored_hmac == computed_hmac:
        print(f"[OK] HMAC verified: {computed_hmac[:16]}...")
        return 0
    else:
        print(f"[FAIL] HMAC MISMATCH - TAMPER DETECTED!")
        print(f"       Stored:   {stored_hmac[:16]}...")
        print(f"       Computed: {computed_hmac[:16]}...")
        return 1


def main():
    parser = argparse.ArgumentParser(description="AEGIS NIDS Rule Management CLI")
    parser.add_argument("--detail", metavar="NAME", help="Show detailed rule info")
    parser.add_argument("--stats", action="store_true", help="Show rule match statistics")
    parser.add_argument("--validate", action="store_true", help="Validate rule file syntax")
    parser.add_argument("--reload", action="store_true", help="Trigger hot-reload via mtime touch")
    parser.add_argument("--sign", action="store_true", help="Generate HMAC-SHA256 for tamper-evidence (OPS-2/IR-13)")
    parser.add_argument("--verify", action="store_true", help="Verify Rules.json HMAC signature")
    args = parser.parse_args()

    if args.detail:
        return show_detail(args.detail)
    if args.stats:
        return show_stats()
    if args.validate:
        return validate_rules()
    if args.reload:
        return trigger_reload()
    if args.sign:
        return generate_hmac()
    if args.verify:
        return verify_hmac()

    return list_rules()


if __name__ == "__main__":
    sys.exit(main())
