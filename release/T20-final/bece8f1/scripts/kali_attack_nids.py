#!/usr/bin/env python3
"""Kali -> NIDs attack script (isolated VMware lab only).

Run ON Kali (normally 192.168.126.10) against the NIDs Windows victim
(normally 192.168.126.20). Stdlib only - no scapy/nmap required
(uses them opportunistically if present).

Covered (network-reachable, 8 rules):
  L7  R0056 SQLi auth bypass, R9064 CMD semicolon, R9059 XSS, R0088 traversal
  L4  R9002 ICMP flood, R9006 SYN scan, R9007 XMAS scan
Host-side rules (KERNEL_FILE/PROCESS, L2_PIPE - 14 rules) cannot be fired
over the network; the script prints their manual host-side steps instead.

Safety: lab host-only network only. Target must be passed explicitly and
must remain inside the lab subnet. NIDs prevention gate stays closed (observe-only):
expect detections, never enforcement.

Usage:
  python3 kali_attack_nids.py --target 192.168.126.20
  python3 kali_attack_nids.py --target 192.168.126.20 --intense
  python3 kali_attack_nids.py --target 192.168.126.20 --only L7
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error

DEFAULT_TARGET = "192.168.126.20"
LAB_SUBNET = "192.168.126."

RESULTS: list[tuple[str, str, str]] = []


def note(rule: str, action: str, outcome: str) -> None:
    RESULTS.append((rule, action, outcome))
    print(f"[{rule}] {action} -> {outcome}", flush=True)


def http_probe(target: str, path: str, timeout: int = 6) -> str:
    url = f"http://{target}/{path.lstrip('/')}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}"
    except Exception as e:
        return f"ERR {type(e).__name__}"


def l7_attacks(target: str, intense: bool) -> None:
    payloads = {
        "R0056": ["login?user=admin' OR 1=1--", "login?user=' OR '1'='1"],
        "R9064": ["ping;id", "exec;cat /etc/passwd"],
        "R9059": ["search?q=<script>alert(1)</script>"],
        "R0088": ["../../etc/passwd", "..\\..\\windows\\system32\\drivers\\etc\\hosts"],
    }
    reps = 3 if intense else 1
    for rid, paths in payloads.items():
        for _ in range(reps):
            for p in paths:
                note(rid, f"GET /{p[:40]}", http_probe(target, p))


def tcp_connect_scan(target: str, ports: list[int], timeout: float = 1.0) -> list[int]:
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((target, port)) == 0:
                open_ports.append(port)
        finally:
            s.close()
    return open_ports


def l4_attacks(target: str, intense: bool) -> None:
    # R9006: TCP connect scan (stealth SYN needs raw sockets; connect scan
    # exercises the same flow-anomaly path when raw is unavailable).
    ports = list(range(20, 103)) if intense else [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080]
    found = tcp_connect_scan(target, ports)
    note("R9006", f"connect scan {len(ports)} ports", f"open={found if found else 'none'}")
    # R9007: XMAS (FIN/PSH/URG) needs root raw sockets; try, else record skip.
    if os.geteuid() == 0 if hasattr(os, "geteuid") else False:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.close()
            note("R9007", "raw socket available", "XMAS via hping3/nmap recommended instead")
        except OSError as e:
            note("R9007", "raw socket blocked", f"SKIP ({e}) - use nmap --scanflags 41")
    else:
        note("R9007", "not root", "SKIP - run as root or use nmap --scanflags 41")
    # R9002: ICMP flood via system ping (count-limited, safe default).
    ping = shutil.which("ping")
    count = "50" if intense else "10"
    if ping:
        proc = subprocess.run([ping, "-c", count, "-i", "0.2", target],
                              capture_output=True, text=True, timeout=60)
        note("R9002", f"ping -c {count} {target}", f"rc={proc.returncode}")
    else:
        note("R9002", "no ping binary", "SKIP")


def host_side_manual() -> None:
    print("\n--- Host-side rules (run ON the Windows NIDs host, observe-only) ---")
    print("KERNEL_FILE R1001-R1005: run_fim_runtime_observe_only_proof.ps1")
    print("KERNEL_PROCESS R2001-R2005: run_etw_runtime_observe_only_proof.ps1")
    print("L2_PIPE R3001-R3005: run_pipe_runtime_observe_only_proof.ps1")
    print("Then on either box: python tools/aegisctl.py incidents list")


def main() -> int:
    ap = argparse.ArgumentParser(description="Kali lab attacks vs NIDs host (observe-only)")
    ap.add_argument(
        "--target", required=True,
        help=f"Explicit lab victim IPv4 address (expected {DEFAULT_TARGET})",
    )
    ap.add_argument("--intense", action="store_true")
    ap.add_argument("--only", choices=["L7", "L4", "all"], default="all")
    args = ap.parse_args()
    if not args.target.startswith(LAB_SUBNET):
        print(f"REFUSE: {args.target} is outside lab subnet {LAB_SUBNET}0/24", file=sys.stderr)
        return 2
    print(f"Kali lab attack: target={args.target} intense={args.intense}")
    if args.only in ("L7", "all"):
        l7_attacks(args.target, args.intense)
    if args.only in ("L4", "all"):
        l4_attacks(args.target, args.intense)
    host_side_manual()
    print("\n--- On the NIDs host, verify detections ---")
    print("python tools/aegisctl.py incidents list")
    print("python tools/aegisctl.py metrics snapshot")
    fails = [r for r in RESULTS if r[2].startswith("ERR") or r[2].startswith("SKIP")]
    print(f"\ndone: {len(RESULTS)} probes, {len(fails)} skipped/errored (target may have no listener)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
