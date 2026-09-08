#!/usr/bin/env python3
"""
aegis_event_gen — Synthetic Event Generator for Gate B integration tests.

Sends synthetic events to the AEGIS pipeline so we can verify the golden
path: bridge → core → brain → aggregator → dashboard.

Two transport modes:
  --pipe   : Send events via the named pipe `\\.\pipe\aegis_nids` (the
             sensor pipe that nids_capture.zig listens on).
  --udp    : Send events via UDP to 127.0.0.1:9999 (the brain's alert
             port — used to test brain IPS directly).
  --tcp    : Send events via TCP to 127.0.0.1:12345 (the core's TCP
             sensor port — used to test Tier-1 detection).

Event schemas (JSON, one per line):
  {"attack_type":"SYN-FLOOD-TEST","src_ip":"1.2.3.4","dst_ip":"5.6.7.8",
   "src_port":12345,"dst_port":80,"protocol":"TCP","severity":"High",
   "policy":"Alert","rule_id":"TEST-001","reason":"Gate-B synthetic"}

Usage:
  python scripts/aegis_event_gen.py --pipe --count 10
  python scripts/aegis_event_gen.py --udp  --count 5  --severity Critical
  python scripts/aegis_event_gen.py --tcp  --count 20 --attack "PORT-SCAN-TEST"
  python scripts/aegis_event_gen.py --pipe --count 1 --wait 0.5

The events are designed to be benign (no actual attack traffic) but to
trigger detection rules so we can verify each stage of the pipeline.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Default synthetic event template. Each field can be overridden via CLI.
DEFAULT_EVENT = {
    "attack_type": "SYN-FLOOD-TEST",
    "src_ip": "1.2.3.4",
    "dst_ip": "5.6.7.8",
    "src_port": 12345,
    "dst_port": 80,
    "protocol": "TCP",
    "severity": "High",
    "policy": "Alert",
    "rule_id": "TEST-001",
    "reason": "Gate-B synthetic event for golden-path verification",
    "source": "aegis_event_gen",
}

# Pipe name (must match nids_capture.zig PIPE_NAME constant)
NIDS_PIPE_NAME = r"\\.\pipe\aegis_nids"

# Default ports (must match docs/runtime/COMPONENT_MATRIX.md §3)
BRAIN_UDP_PORT = 9999
CORE_TCP_PORT = 12345


def send_via_pipe(event: dict) -> bool:
    """Send a single event via the named pipe \\.\pipe\\aegis_nids.

    Returns True on success, False on failure.
    On non-Windows platforms, returns False (named pipes are Windows-only).
    """
    if sys.platform != "win32":
        print("  [pipe] SKIP: named pipes are Windows-only")
        return False
    try:
        import win32file  # type: ignore
        import win32pipe   # type: ignore
    except ImportError:
        print("  [pipe] SKIP: pywin32 not installed")
        return False

    payload = json.dumps(event) + "\n"
    payload_bytes = payload.encode("utf-8")

    try:
        # Wait for the pipe to be available (5s timeout)
        win32pipe.WaitNamedPipe(NIDS_PIPE_NAME, 5000)
        handle = win32file.CreateFile(
            NIDS_PIPE_NAME,
            win32file.GENERIC_WRITE,
            0, None,
            win32file.OPEN_EXISTING,
            0, None,
        )
        try:
            win32file.WriteFile(handle, payload_bytes)
            return True
        finally:
            win32file.CloseHandle(handle)
    except Exception as e:
        print(f"  [pipe] ERROR: {e}")
        return False


def send_via_udp(event: dict, host: str = "127.0.0.1", port: int = BRAIN_UDP_PORT) -> bool:
    """Send a single event via UDP to the brain's alert port."""
    payload = json.dumps(event).encode("utf-8")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2.0)
            s.sendto(payload, (host, port))
        return True
    except Exception as e:
        print(f"  [udp]  ERROR: {e}")
        return False


def send_via_tcp(event: dict, host: str = "127.0.0.1", port: int = CORE_TCP_PORT) -> bool:
    """Send a single event via TCP to the core's TCP sensor port."""
    payload = json.dumps(event) + "\n"
    payload_bytes = payload.encode("utf-8")
    try:
        with socket.create_connection((host, port), timeout=5.0) as s:
            s.sendall(payload_bytes)
        return True
    except Exception as e:
        print(f"  [tcp]  ERROR: {e}")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="aegis_event_gen",
        description="Synthetic event generator for AEGIS Gate B integration tests",
    )

    transport = parser.add_mutually_exclusive_group(required=True)
    transport.add_argument("--pipe", action="store_true",
                           help="Send via named pipe \\\\.\\pipe\\aegis_nids (Windows only)")
    transport.add_argument("--udp",  action="store_true",
                           help="Send via UDP to 127.0.0.1:9999 (brain alert port)")
    transport.add_argument("--tcp",  action="store_true",
                           help="Send via TCP to 127.0.0.1:12345 (core sensor port)")

    parser.add_argument("--count", type=int, default=1,
                        help="Number of events to send (default: 1)")
    parser.add_argument("--wait", type=float, default=0.1,
                        help="Seconds to wait between events (default: 0.1)")
    parser.add_argument("--attack", default=DEFAULT_EVENT["attack_type"],
                        help=f"Attack type (default: {DEFAULT_EVENT['attack_type']})")
    parser.add_argument("--severity", default=DEFAULT_EVENT["severity"],
                        choices=["Low", "Medium", "High", "Critical"],
                        help=f"Severity (default: {DEFAULT_EVENT['severity']})")
    parser.add_argument("--policy", default=DEFAULT_EVENT["policy"],
                        choices=["Alert", "Block", "Drop"],
                        help=f"Policy (default: {DEFAULT_EVENT['policy']})")
    parser.add_argument("--src-ip", default=DEFAULT_EVENT["src_ip"],
                        help=f"Source IP (default: {DEFAULT_EVENT['src_ip']})")
    parser.add_argument("--rule-id", default=DEFAULT_EVENT["rule_id"],
                        help=f"Rule ID (default: {DEFAULT_EVENT['rule_id']})")
    parser.add_argument("--port", type=int, default=None,
                        help="Override destination port (applies to UDP/TCP only)")

    args = parser.parse_args()

    # Build the event from the template + CLI overrides
    event = DEFAULT_EVENT.copy()
    event["attack_type"] = args.attack
    event["severity"] = args.severity
    event["policy"] = args.policy
    event["src_ip"] = args.src_ip
    event["rule_id"] = args.rule_id
    event["timestamp"] = int(time.time())

    # Pick the transport function
    if args.pipe:
        transport_name = "pipe"
        send_fn = lambda e: send_via_pipe(e)
    elif args.udp:
        transport_name = "udp"
        port = args.port or BRAIN_UDP_PORT
        send_fn = lambda e: send_via_udp(e, port=port)
        print(f"Sending {args.count} event(s) via UDP to 127.0.0.1:{port}")
    else:  # tcp
        transport_name = "tcp"
        port = args.port or CORE_TCP_PORT
        send_fn = lambda e: send_via_tcp(e, port=port)
        print(f"Sending {args.count} event(s) via TCP to 127.0.0.1:{port}")

    if transport_name == "pipe":
        print(f"Sending {args.count} event(s) via named pipe {NIDS_PIPE_NAME}")

    print(f"Event template: {json.dumps(event, separators=(',', ':'))}")
    print()

    success = 0
    failed = 0
    for i in range(args.count):
        # Vary the source port + IP slightly so each event is unique
        event["src_port"] = 12345 + i
        event["timestamp"] = int(time.time())

        ok = send_fn(event)
        if ok:
            success += 1
            print(f"  [{i+1}/{args.count}] OK   {event['attack_type']} from {event['src_ip']}:{event['src_port']}")
        else:
            failed += 1
            print(f"  [{i+1}/{args.count}] FAIL {event['attack_type']} from {event['src_ip']}:{event['src_port']}")

        if i < args.count - 1 and args.wait > 0:
            time.sleep(args.wait)

    print()
    print(f"Summary: {success} sent, {failed} failed (transport: {transport_name})")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
