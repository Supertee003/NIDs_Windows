#!/usr/bin/env python3
"""
aegis_alerts.py - AEGIS NIDS Alert Viewer & Acknowledgement (Phase 16, UX-05)

Views alerts from logs/aegis_core.ndjson and supports acknowledgement.
Alert ack state is persisted in logs/acknowledged_alerts.json.

Usage:
  python aegis_alerts.py                    # Show recent alerts (last 50)
  python aegis_alerts.py --all              # Show all alerts
  python aegis_alerts.py --tail              # Tail new alerts (live)
  python aegis_alerts.py --ack <id>         # Acknowledge alert by line number
  python aegis_alerts.py --unacked           # Show only unacknowledged
  python aegis_alerts.py --filter BLOCK     # Filter by event type
  python aegis_alerts.py --filter MATCH      # Show only MATCH events
"""

import argparse
import json
import sys
import time
from pathlib import Path

AEGIS_ROOT = Path(__file__).parent.parent
LOG_FILE = AEGIS_ROOT / "logs" / "aegis_core.ndjson"
ACK_FILE = AEGIS_ROOT / "logs" / "acknowledged_alerts.json"


def load_acked() -> set:
    """Load acknowledged alert IDs."""
    if not ACK_FILE.exists():
        return set()
    try:
        return set(json.loads(ACK_FILE.read_text()))
    except (json.JSONDecodeError, OSError):
        return set()


def save_acked(acked: set):
    """Save acknowledged alert IDs."""
    ACK_FILE.parent.mkdir(parents=True, exist_ok=True)
    ACK_FILE.write_text(json.dumps(list(acked)))


def read_alerts(limit=None, event_filter=None, unacked_only=False):
    """Read alerts from NDJSON log file."""
    if not LOG_FILE.exists():
        print(f"[ERROR] Log file not found: {LOG_FILE}", file=sys.stderr)
        return []

    acked = load_acked() if unacked_only else set()
    alerts = []

    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    event = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue

                if event_filter and event.get("event") != event_filter:
                    continue

                if unacked_only and str(line_num) in acked:
                    continue

                event['_line_num'] = line_num
                alerts.append(event)
    except OSError as e:
        print(f"[ERROR] Failed to read log: {e}", file=sys.stderr)
        return []

    if limit:
        alerts = alerts[-limit:]

    return alerts


def print_alerts(alerts):
    """Print alerts in formatted table."""
    if not alerts:
        print("[INFO] No alerts found.")
        return 0

    acked = load_acked()

    print("=" * 80)
    print(f"  AEGIS NIDS Alerts ({len(alerts)} shown)")
    print("=" * 80)
    print(f"{'ID':>6}  {'Time':<20}  {'Level':<8}  {'Event':<12}  {'Rule/IP':<25}  {'Ack':>3}")
    print("-" * 80)

    for alert in alerts:
        line_num = alert.get('_line_num', '?')
        ts_ms = alert.get('ts_ms', 0)
        ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_ms / 1000)) if ts_ms else '?'

        level = alert.get('level', '?')
        event = alert.get('event', '?')

        rule = alert.get('rule', '')
        src_ip = alert.get('src_ip', '')
        detail = rule or src_ip or '-'

        is_acked = 'Y' if str(line_num) in acked else '-'

        print(f"{line_num:>6}  {ts_str:<20}  {level:<8}  {event:<12}  {detail:<25}  {is_acked:>3}")

    print("=" * 80)
    print(f"  Acknowledged: {len(acked)} / {alerts[-1].get('_line_num', 0)} total")
    return 0


def acknowledge(line_num: int) -> int:
    """Acknowledge an alert by line number."""
    acked = load_acked()
    acked.add(str(line_num))
    save_acked(acked)
    print(f"[OK] Acknowledged alert #{line_num}")
    return 0


def tail_alerts():
    """Tail new alerts in real-time."""
    if not LOG_FILE.exists():
        print(f"[ERROR] Log file not found: {LOG_FILE}", file=sys.stderr)
        return 1

    print(f"[TAIL] Watching {LOG_FILE} for new alerts (Ctrl+C to stop)...")
    print("=" * 80)

    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        f.seek(0, 2)  # End of file
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                try:
                    event = json.loads(line.strip())
                    ts_ms = event.get('ts_ms', 0)
                    ts_str = time.strftime('%H:%M:%S', time.localtime(ts_ms / 1000)) if ts_ms else '?'
                    level = event.get('level', '?')
                    event_type = event.get('event', '?')
                    rule = event.get('rule', '')
                    src_ip = event.get('src_ip', '')
                    detail = rule or src_ip or '-'
                    print(f"  [{ts_str}] {level:8s} {event_type:12s} {detail}")
                except json.JSONDecodeError:
                    continue
        except KeyboardInterrupt:
            print("\n[TAIL] Stopped.")
            return 0


def main():
    parser = argparse.ArgumentParser(description="AEGIS NIDS Alert Viewer")
    parser.add_argument("--all", action="store_true", help="Show all alerts (no limit)")
    parser.add_argument("--tail", action="store_true", help="Tail new alerts live")
    parser.add_argument("--ack", type=int, metavar="ID", help="Acknowledge alert by line number")
    parser.add_argument("--unacked", action="store_true", help="Show only unacknowledged")
    parser.add_argument("--filter", choices=["BLOCK", "MATCH", "FORWARD", "IP_BLOCKED", "REJECTED"],
                        help="Filter by event type")
    parser.add_argument("--limit", type=int, default=50, help="Max alerts to show (default: 50)")
    args = parser.parse_args()

    if args.tail:
        return tail_alerts()

    if args.ack:
        return acknowledge(args.ack)

    limit = None if args.all else args.limit
    alerts = read_alerts(limit=limit, event_filter=args.filter, unacked_only=args.unacked)
    return print_alerts(alerts)


if __name__ == "__main__":
    sys.exit(main())
