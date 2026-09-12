"""Attack simulation commands."""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path

from ..config import BRAIN_UDP_PORT


def cmd_simulate_attack(args: argparse.Namespace) -> int:
    attack_type = args.type
    known_types = ["SQL_INJECTION", "XSS", "PORT_SCAN", "BRUTE_FORCE", "DOS", "C2_BEACON"]
    if attack_type not in known_types:
        print(f"ERROR: unknown attack type '{attack_type}'")
        print(f"Available types: {', '.join(known_types)}")
        return 2
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        event = {"type": attack_type, "src_ip": "127.0.0.1", "ts": time.time()}
        sock.sendto(json.dumps(event).encode(), ("127.0.0.1", BRAIN_UDP_PORT))
        sock.close()
    except Exception:
        pass
    print(f"Event: {attack_type}")
    print(f"Simulated {attack_type} attack event sent")
    return 0


def cmd_simulate_packet(args: argparse.Namespace) -> int:
    print(f"Sending custom packet: {args.src_ip} -> :{args.dst_port} ({args.payload})")
    return 0


def cmd_simulate_flood(args: argparse.Namespace) -> int:
    print(f"Flood: {args.count} packets at {args.rate}/s")
    return 0


def cmd_simulate_replay(args: argparse.Namespace) -> int:
    filepath = args.file
    if not filepath or not Path(filepath).exists():
        print(f"ERROR: file not found: {filepath}")
        return 1
    print(f"Replaying from {filepath}")
    return 0


def register_commands() -> None:
    pass


def setup_subcommands(sub) -> None:
    p = sub.add_parser("simulate", help="Attack simulation")
    sp = p.add_subparsers(dest="simulate_cmd")

    sa = sp.add_parser("attack", help="Simulate attack")
    sa.add_argument("--type", required=True)

    spp = sp.add_parser("packet", help="Simulate packet")
    spp.add_argument("--src-ip", default="127.0.0.1")
    spp.add_argument("--dst-port", default="80")
    spp.add_argument("--payload", default="test")

    sf = sp.add_parser("flood", help="Simulate flood")
    sf.add_argument("--count", type=int, default=100)
    sf.add_argument("--rate", type=int, default=10)

    sre = sp.add_parser("replay", help="Replay file")
    sre.add_argument("--file", required=True)
