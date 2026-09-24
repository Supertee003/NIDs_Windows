#!/usr/bin/env python3
"""
aegis_unblock.py - AEGIS NIDS Manual IP Unblock CLI (Phase 13, UX-04)

Sends an unblock request to the AEGIS core via UDP control channel.

Usage:
  python aegis_unblock.py 192.168.1.100
  python aegis_unblock.py --all        # Unblock all IPs (use with caution)
"""

import argparse
import json
import re
import socket
import sys
from pathlib import Path

BRAIN_UDP_PORT = 9999
BRAIN_UDP_HOST = "127.0.0.1"
BLOCKED_IPS_FILE = Path(__file__).parent.parent / "logs" / "blocked_ips.json"


def validate_ip(ip: str) -> bool:
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)
    if not match:
        return False
    for octet in match.groups():
        if int(octet) > 255:
            return False
    return True


def send_unblock_request(ip: str) -> bool:
    message = {
        "cmd": "unblock_ip",
        "ip": ip,
        "source": "aegis_unblock.py CLI",
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
        print(f"[ERROR] Failed to send unblock request: {e}", file=sys.stderr)
        return False


def unblock_all() -> int:
    """Read blocked_ips.json and unblock each IP."""
    if not BLOCKED_IPS_FILE.exists():
        print("[INFO] No blocked IPs file found.")
        return 0

    try:
        data = json.loads(BLOCKED_IPS_FILE.read_text())
        if not data:
            print("[INFO] No IPs to unblock.")
            return 0

        print(f"[UNBLOCK] Processing {len(data)} IPs...")
        success = 0
        for ip in data:
            if send_unblock_request(ip):
                print(f"  [OK]    Unblock request sent for {ip}")
                success += 1
            else:
                print(f"  [FAIL]  Failed to unblock {ip}")

        print(f"\n[SUMMARY] {success}/{len(data)} unblock requests sent")
        return 0 if success == len(data) else 1
    except (json.JSONDecodeError, OSError) as e:
        print(f"[ERROR] Failed to read blocked IPs: {e}", file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="AEGIS NIDS Manual IP Unblock CLI"
    )
    parser.add_argument(
        "ip",
        nargs="?",
        help="IPv4 address to unblock (e.g., 192.168.1.100)"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Unblock all currently blocked IPs"
    )
    args = parser.parse_args()

    if args.all:
        return unblock_all()

    if not args.ip:
        parser.print_help()
        return 1

    if not validate_ip(args.ip):
        print(f"[ERROR] Invalid IP address: {args.ip}", file=sys.stderr)
        return 1

    print(f"[UNBLOCK] Sending unblock request for {args.ip}")

    if send_unblock_request(args.ip):
        print(f"[OK]      Unblock request sent to brain")
        return 0
    else:
        print(f"[FAIL]    Unblock request failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
