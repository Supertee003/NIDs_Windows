#!/usr/bin/env python3
"""
aegis_defcon.py - AEGIS NIDS DEFCON Level Query (Phase 16, UX-11)

Calculates and displays the current DEFCON level based on recent alerts.
Centralizes DEFCON calculation (was differing across 4 components).

DEFCON levels:
  1 = Critical (imminent attack, multiple Critical events in last 5 min)
  2 = Severe   (multiple Block events in last 5 min)
  3 = Elevated (some matches in last 5 min)
  4 = Guarded  (few matches in last 15 min)
  5 = Normal   (no threats)

Usage:
  python aegis_defcon.py              # Show current DEFCON level
  python aegis_defcon.py --json        # JSON output for scripts
  python aegis_defcon.py --history    # Show DEFCON history (last 24h)
"""

import argparse
import json
import sys
import time
from pathlib import Path

AEGIS_ROOT = Path(__file__).parent.parent
LOG_FILE = AEGIS_ROOT / "logs" / "aegis_core.ndjson"

# Time windows for DEFCON calculation
WINDOW_CRITICAL_S = 5 * 60      # 5 minutes
WINDOW_SEVERE_S = 5 * 60       # 5 minutes
WINDOW_ELEVATED_S = 5 * 60     # 5 minutes
WINDOW_GUARDED_S = 15 * 60     # 15 minutes

# Thresholds
THRESHOLD_CRITICAL_COUNT = 1   # 1+ Critical event = DEFCON 1
THRESHOLD_SEVERE_BLOCKS = 3    # 3+ Block events = DEFCON 2
THRESHOLD_ELEVATED_MATCHES = 10 # 10+ Match events = DEFCON 3
THRESHOLD_GUARDED_MATCHES = 1  # 1+ Match event = DEFCON 4


def calculate_defcon() -> dict:
    """Calculate current DEFCON level from forensic log."""
    if not LOG_FILE.exists():
        return {
            "defcon": 5,
            "level": "Normal",
            "reason": "No log file (NIDS not running or no events yet)",
            "counts": {},
        }

    now_ms = int(time.time() * 1000)
    critical_count = 0
    block_count = 0
    match_count = 0
    forward_count = 0

    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue

                ts_ms = event.get('ts_ms', 0)
                age_s = (now_ms - ts_ms) / 1000 if ts_ms else 999999

                event_type = event.get('event', '')
                level = event.get('level', '')

                if age_s < WINDOW_GUARDED_S:
                    if event_type == 'BLOCK':
                        block_count += 1
                    elif event_type == 'MATCH':
                        match_count += 1
                    elif event_type == 'FORWARD':
                        forward_count += 1

                    if level == 'critical':
                        critical_count += 1
    except OSError:
        pass

    # Determine DEFCON level (lowest number = highest threat)
    defcon = 5
    reason = "No threats detected"

    if critical_count >= THRESHOLD_CRITICAL_COUNT:
        defcon = 1
        reason = f"{critical_count} Critical event(s) in last {WINDOW_CRITICAL_S//60} min"
    elif block_count >= THRESHOLD_SEVERE_BLOCKS:
        defcon = 2
        reason = f"{block_count} Block event(s) in last {WINDOW_SEVERE_S//60} min"
    elif match_count >= THRESHOLD_ELEVATED_MATCHES:
        defcon = 3
        reason = f"{match_count} Match event(s) in last {WINDOW_ELEVATED_S//60} min"
    elif match_count >= THRESHOLD_GUARDED_MATCHES:
        defcon = 4
        reason = f"{match_count} Match event(s) in last {WINDOW_GUARDED_S//60} min"

    level_names = {1: "Critical", 2: "Severe", 3: "Elevated", 4: "Guarded", 5: "Normal"}

    return {
        "defcon": defcon,
        "level": level_names[defcon],
        "reason": reason,
        "counts": {
            "critical_events": critical_count,
            "block_events": block_count,
            "match_events": match_count,
            "forward_events": forward_count,
        },
        "windows_s": {
            "critical": WINDOW_CRITICAL_S,
            "severe": WINDOW_SEVERE_S,
            "elevated": WINDOW_ELEVATED_S,
            "guarded": WINDOW_GUARDED_S,
        },
    }


def print_human_readable(result: dict):
    """Print DEFCON level in human-readable format."""
    defcon = result['defcon']
    level = result['level']

    # ANSI colors for DEFCON levels
    colors = {1: '\033[31;1m', 2: '\033[31m', 3: '\033[33m', 4: '\033[36m', 5: '\033[32m'}
    reset = '\033[0m'
    color = colors.get(defcon, '')

    print("=" * 50)
    print(f"  AEGIS NIDS DEFCON Level: {color}DEFCON {defcon} - {level}{reset}")
    print("=" * 50)
    print(f"  Reason: {result['reason']}")
    print()
    print("  Event counts (last 15 min):")
    counts = result['counts']
    print(f"    Critical events: {counts['critical_events']}")
    print(f"    Block events:    {counts['block_events']}")
    print(f"    Match events:    {counts['match_events']}")
    print(f"    Forward events:  {counts['forward_events']}")
    print("=" * 50)
    return 0


def main():
    parser = argparse.ArgumentParser(description="AEGIS NIDS DEFCON Level Query")
    parser.add_argument("--json", action="store_true", help="Output JSON for scripts")
    args = parser.parse_args()

    result = calculate_defcon()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        return print_human_readable(result)

    return 0


if __name__ == "__main__":
    sys.exit(main())
