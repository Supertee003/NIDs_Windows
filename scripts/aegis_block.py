#!/usr/bin/env python3
"""
aegis_block.py - AEGIS NIDS Manual IP Block CLI (Phase 13, UX-04)

Sends a block request to the AEGIS core via UDP control channel.
The core (nids_analyze.zig) will call wfp_ioctl.block_ip() to install
a kernel WFP filter.

Usage:
  python aegis_block.py 192.168.1.100
  python aegis_block.py 192.168.1.100 "SQL injection attempt"
  python aegis_block.py --list          # Show currently blocked IPs

Note: This sends a UDP message to the brain on port 9999, which
forwards to the core. For direct WFP IOCTL, use the dashboard API.
"""

import argparse
import json
import os
import re
import socket
import sys
from pathlib import Path

# ============================================================
# Configuration
# ============================================================

BRAIN_UDP_PORT = 9999
BRAIN_UDP_HOST = "127.0.0.1"
BLOCKED_IPS_FILE = Path(__file__).parent.parent / "logs" / "blocked_ips.json"


def validate_ip(ip: str) -> bool:
    """Validate IPv4 address format."""
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)
    if not match:
        return False
    for octet in match.groups():
        if int(octet) > 255:
            return False
    return True


def send_block_request(ip: str, reason: str) -> bool:
    """Send block request to brain via UDP."""
    message = {
        "cmd": "block_ip",
        "ip": ip,
        "reason": reason,
        "source": "aegis_block.py CLI",
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.sendto(
            json.dumps(message).encode('utf-8'),
            (BRAIN_UDP_HOST, BRAIN_UDP_PORT)
        )
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"[ERROR] Failed to send block request: {e}", file=sys.stderr)
        return False


def list_blocked_ips():
    """Read and display blocked IPs from logs/blocked_ips.json."""
    if not BLOCKED_IPS_FILE.exists():
        print("[INFO] No blocked IPs file found (logs/blocked_ips.json)")
        print("       This means either:")
        print("       1. AEGIS core has not blocked any IPs, OR")
        print("       2. AEGIS core is not running")
        return 0

    try:
        data = json.loads(BLOCKED_IPS_FILE.read_text())
        if not data:
            print("[INFO] No IPs currently blocked.")
            return 0

        print("=" * 50)
        print(f"  Blocked IPs ({len(data)} total)")
        print("=" * 50)
        for i, ip in enumerate(data, 1):
            print(f"  {i:3d}. {ip}")
        print("=" * 50)
        return 0
    except (json.JSONDecodeError, OSError) as e:
        print(f"[ERROR] Failed to read blocked IPs: {e}", file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="AEGIS NIDS Manual IP Block CLI"
    )
    parser.add_argument(
        "ip",
        nargs="?",
        help="IPv4 address to block (e.g., 192.168.1.100)"
    )
    parser.add_argument(
        "reason",
        nargs="?",
        default="Manual block via CLI",
        help="Reason for blocking (optional)"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List currently blocked IPs and exit"
    )
    args = parser.parse_args()

    if args.list:
        return list_blocked_ips()

    if not args.ip:
        parser.print_help()
        return 1

    if not validate_ip(args.ip):
        print(f"[ERROR] Invalid IP address: {args.ip}", file=sys.stderr)
        print("        Expected format: XXX.XXX.XXX.XXX (each octet 0-255)", file=sys.stderr)
        return 1

    print(f"[BLOCK] Sending block request for {args.ip}")
    print(f"        Reason: {args.reason}")

    if send_block_request(args.ip, args.reason):
        print(f"[OK]    Block request sent to brain (UDP {BRAIN_UDP_HOST}:{BRAIN_UDP_PORT})")
        print(f"        The brain will forward to core, which calls wfp_ioctl.block_ip()")
        print(f"        Kernel WFP filter will be installed within ~1 second")
        return 0
    else:
        print(f"[FAIL]  Block request failed - is AEGIS core running?", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
