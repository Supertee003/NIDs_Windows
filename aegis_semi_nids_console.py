#!/usr/bin/env python3
"""
aegis_semi_nids_console.py — AEGIS Semi-NIDS Interactive Console
                                 (Human-in-the-Loop)

Property 3 Implementation: Interactive Control Loop
- แสดง Pending Alerts ที่รอการตัดสินใจจากผู้ดูแลระบบ
- ผู้ดูแลสามารถกด: [Block IP] [Block Temp] [Whitelist] [Ignore] [Escalate]
- แสดง Fail-Open Status, Blocked IPs, Engine Stats แบบ real-time
- Console refresh ทุก 1 วินาที พร้อม ANSI color

FFI: เรียก Rust semi_nids engine ผ่าน ctypes (aegis_shield.dll/.so)
"""

import ctypes
import os
import sys
import time
import threading
import signal
import struct
from datetime import datetime, timedelta
from typing import Optional, List, Tuple

# ═══════════════════════════════════════════════════════════════
# ANSI Colors
# ═══════════════════════════════════════════════════════════════
RST  = "\033[0m"
BOLD = "\033[1m"
DIM  = "\033[2m"
RED  = "\033[31m"
GRN  = "\033[32m"
YEL  = "\033[33m"
BLU  = "\033[34m"
MAG  = "\033[35m"
CYN  = "\033[36m"
WHT  = "\033[37m"
BG_RED   = "\033[41m"
BG_GRN   = "\033[42m"
BG_YEL   = "\033[43m"
BG_BLU   = "\033[44m"
BG_MAG   = "\033[45m"
BG_CYN   = "\033[46m"
BRED  = BOLD + RED
BGRN  = BOLD + GRN
BYEL  = BOLD + YEL
BBLU  = BOLD + BLU
BCYN  = BOLD + CYN
BMAG  = BOLD + MAG
BWHT  = BOLD + WHT

# ═══════════════════════════════════════════════════════════════
# Decision / Confidence / Human Decision Constants (match Rust)
# ═══════════════════════════════════════════════════════════════
DECISION_NAMES = {
    0: ("Pass",             GRN),
    1: ("Alert Only",       YEL),
    2: ("Rate Limit",       MAG),
    3: ("Block",            RED),
    4: ("Block+Preserve",   BRED),
    5: ("Pending Human",    CYN),
}

CONFIDENCE_NAMES = {
    0: ("Unknown",  DIM),
    1: ("Low",      BLU),
    2: ("Medium",   YEL),
    3: ("High",     MAG),
    4: ("Critical", RED),
}

HUMAN_DECISION_NAMES = {
    0: "None",
    1: "Block",
    2: "Block Temp",
    3: "Whitelist",
    4: "Ignore",
    5: "Escalate",
}

LOAD_STATE_NAMES = {
    0: ("Normal",     GRN),
    1: ("Elevated",   YEL),
    2: ("Overloaded", RED),
    3: ("Critical",   BRED),
}

# ═══════════════════════════════════════════════════════════════
# FFI Bridge to Rust semi_nids engine
# ═══════════════════════════════════════════════════════════════

class SemiNidsBridge:
    """ctypes bridge to aegis_shield.dll/.so Semi-NIDS FFI exports."""

    def __init__(self):
        self.lib = None
        self._load()

    def _load(self):
        paths = [
            "aegis_shield.dll",
            "aegis_shield.so",
            "libaegis_shield.so",
            os.path.join(os.path.dirname(__file__), "..", "shield_rust",
                         "target", "release", "aegis_shield.dll"),
            os.path.join(os.path.dirname(__file__), "..", "shield_rust",
                         "target", "release", "libaegis_shield.so"),
        ]
        for p in paths:
            try:
                self.lib = ctypes.CDLL(p)
                break
            except OSError:
                continue

        if self.lib is None:
            return

        # Set return types and argument types
        self.lib.aegis_semi_nids_init.restype = ctypes.c_int

        self.lib.aegis_semi_nids_evaluate.restype = ctypes.c_uint8
        self.lib.aegis_semi_nids_evaluate.argtypes = [
            ctypes.c_uint32,   # src_ip
            ctypes.c_uint32,   # dst_ip
            ctypes.c_uint16,   # src_port
            ctypes.c_uint16,   # dst_port
            ctypes.c_uint8,    # ip_proto
            ctypes.c_double,   # threat_score
            ctypes.c_uint8,    # confidence
            ctypes.c_uint32,   # risk_flags
            ctypes.c_uint32,   # process_id
        ]

        self.lib.aegis_semi_nids_set_policy.restype = ctypes.c_int
        self.lib.aegis_semi_nids_set_policy.argtypes = [
            ctypes.c_uint64,   # alert_id
            ctypes.c_uint8,    # decision
        ]

        self.lib.aegis_semi_nids_get_pending_count.restype = ctypes.c_uint32

        self.lib.aegis_semi_nids_get_pending.restype = ctypes.c_int
        self.lib.aegis_semi_nids_get_pending.argtypes = [
            ctypes.c_uint32,   # index
            ctypes.POINTER(ctypes.c_uint64),  # out_alert_id
            ctypes.POINTER(ctypes.c_uint32),  # out_src_ip
            ctypes.POINTER(ctypes.c_double),  # out_threat_score
            ctypes.POINTER(ctypes.c_uint8),   # out_confidence
            ctypes.POINTER(ctypes.c_uint8),   # out_decision
        ]

        self.lib.aegis_semi_nids_fail_open_status.restype = ctypes.c_uint8
        self.lib.aegis_semi_nids_fail_open_status.argtypes = [
            ctypes.POINTER(ctypes.c_bool),    # out_active
            ctypes.POINTER(ctypes.c_uint8),   # out_cpu_pct
            ctypes.POINTER(ctypes.c_uint8),   # out_queue_pct
        ]

        self.lib.aegis_semi_nids_update_load.restype = None
        self.lib.aegis_semi_nids_update_load.argtypes = [
            ctypes.c_uint8,   # cpu_pct
            ctypes.c_uint8,   # queue_pct
            ctypes.c_uint64,  # pps
        ]

        self.lib.aegis_semi_nids_block_ip.restype = ctypes.c_int
        self.lib.aegis_semi_nids_block_ip.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32
        ]

        self.lib.aegis_semi_nids_unblock_ip.restype = ctypes.c_int
        self.lib.aegis_semi_nids_unblock_ip.argtypes = [ctypes.c_uint32]

        self.lib.aegis_semi_nids_maintenance.restype = ctypes.c_uint32
        self.lib.aegis_semi_nids_shutdown.restype = None

    @property
    def available(self) -> bool:
        return self.lib is not None

    def init(self) -> int:
        if not self.available: return -1
        return self.lib.aegis_semi_nids_init()

    def evaluate(self, src_ip: int, dst_ip: int, src_port: int, dst_port: int,
                 ip_proto: int, threat_score: float, confidence: int,
                 risk_flags: int, process_id: int) -> int:
        if not self.available: return 0
        return self.lib.aegis_semi_nids_evaluate(
            src_ip, dst_ip, src_port, dst_port, ip_proto,
            threat_score, confidence, risk_flags, process_id
        )

    def set_policy(self, alert_id: int, decision: int) -> int:
        if not self.available: return -1
        return self.lib.aegis_semi_nids_set_policy(alert_id, decision)

    def get_pending_count(self) -> int:
        if not self.available: return 0
        return self.lib.aegis_semi_nids_get_pending_count()

    def get_pending(self, index: int) -> Optional[Tuple]:
        if not self.available: return None
        alert_id = ctypes.c_uint64(0)
        src_ip = ctypes.c_uint32(0)
        threat_score = ctypes.c_double(0.0)
        confidence = ctypes.c_uint8(0)
        decision = ctypes.c_uint8(0)
        rc = self.lib.aegis_semi_nids_get_pending(
            index,
            ctypes.byref(alert_id), ctypes.byref(src_ip),
            ctypes.byref(threat_score), ctypes.byref(confidence),
            ctypes.byref(decision)
        )
        if rc != 0:
            return None
        return (alert_id.value, src_ip.value, threat_score.value,
                confidence.value, decision.value)

    def fail_open_status(self) -> dict:
        if not self.available: return {"load_state": 0, "active": False, "cpu_pct": 0, "queue_pct": 0}
        out_active = ctypes.c_bool()
        out_cpu = ctypes.c_uint8()
        out_queue = ctypes.c_uint8()
        load_state = self.lib.aegis_semi_nids_fail_open_status(
            ctypes.byref(out_active), ctypes.byref(out_cpu), ctypes.byref(out_queue)
        )
        return {
            "load_state": load_state,
            "active": out_active.value,
            "cpu_pct": out_cpu.value,
            "queue_pct": out_queue.value,
        }

    def update_load(self, cpu: int, queue: int, pps: int):
        if not self.available: return
        self.lib.aegis_semi_nids_update_load(cpu, queue, pps)

    def block_ip(self, ip: int, reason: int = 0) -> int:
        if not self.available: return -1
        return self.lib.aegis_semi_nids_block_ip(ip, reason)

    def unblock_ip(self, ip: int) -> int:
        if not self.available: return -1
        return self.lib.aegis_semi_nids_unblock_ip(ip)

    def maintenance(self) -> int:
        if not self.available: return 0
        return self.lib.aegis_semi_nids_maintenance()

    def shutdown(self):
        if not self.available: return
        self.lib.aegis_semi_nids_shutdown()


# ═══════════════════════════════════════════════════════════════
# Helper: IP formatting
# ═══════════════════════════════════════════════════════════════
def ip_str(ip_int: int) -> str:
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"

def ip_int(ip_str_val: str) -> int:
    parts = ip_str_val.strip().split(".")
    if len(parts) != 4:
        return 0
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


# ═══════════════════════════════════════════════════════════════
# Semi-NIDS Interactive Console
# ═══════════════════════════════════════════════════════════════

class SemiNidsConsole:
    """Interactive console for Semi-NIDS Human-in-the-Loop control.

    Displays:
    - System status (fail-open, load state, PPS)
    - Pending alerts requiring human decision
    - Blocked IP list
    - Engine statistics

    Commands:
    - [number] Block IP     — Block the source IP of alert #number permanently
    - t[number] Temp Block  — Temporary block (5 min)
    - w[number] Whitelist   — Whitelist the source IP
    - i[number] Ignore      — Dismiss alert without action
    - e[number] Escalate    — Escalate to higher DEFCON
    - block <ip>            — Manually block an IP
    - unblock <ip>          — Manually unblock/whitelist an IP
    - refresh               — Force refresh
    - stats                 — Show detailed stats
    - quit                  — Exit console
    """

    def __init__(self):
        self.bridge = SemiNidsBridge()
        self.running = True
        self.refresh_interval = 1.0
        self.last_maintenance = time.time()
        self.sim_mode = False  # Simulation mode when DLL not available

        # Simulation state (for demo without Rust DLL)
        self.sim_pending = []
        self.sim_blocked = set()
        self.sim_whitelisted = set()
        self.sim_stats = {
            "evaluated": 0, "passed": 0, "alerted": 0,
            "blocked": 0, "rate_limited": 0, "fail_open_passes": 0,
        }

    def init(self):
        if self.bridge.available:
            rc = self.bridge.init()
            if rc == 0:
                print(f"{BGRN}✓{RST} Semi-NIDS engine initialized (Rust FFI)")
                return True
            else:
                print(f"{BRED}✗{RST} Semi-NIDS engine init failed (rc={rc})")
                return False
        else:
            print(f"{BYEL}⚠{RST} Rust DLL not found — running in {BCYN}simulation mode{RST}")
            self.sim_mode = True
            return True

    def shutdown(self):
        self.running = False
        if self.bridge.available:
            self.bridge.shutdown()
        print(f"\n{DIM}Semi-NIDS console shut down.{RST}")

    # ── Display Functions ─────────────────────────────────────

    def _clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def _draw_header(self):
        now = datetime.now().strftime("%H:%M:%S")
        mode = f"{BCYN}SIMULATION{RST}" if self.sim_mode else f"{BGRN}LIVE (Rust FFI){RST}"
        print(f"{BOLD}{BG_BLU}{WHT} AEGIS Semi-NIDS Console — Human-in-the-Loop Control {RST}")
        print(f"  {DIM}Time: {now}  │  Mode: {mode}  │  Refresh: {self.refresh_interval}s{RST}")
        print(f"  {DIM}Type 'help' for commands, 'quit' to exit{RST}")

    def _draw_fail_open_status(self):
        if self.sim_mode:
            load = 0
            cpu_pct = 0
            queue_pct = 0
            active = False
        else:
            status = self.bridge.fail_open_status()
            load = status.get("load_state", 0)
            cpu_pct = status.get("cpu_pct", 0)
            queue_pct = status.get("queue_pct", 0)
            active = status.get("active", False)

        name, color = LOAD_STATE_NAMES.get(load, ("???", WHT))

        if load >= 2:
            status_icon = f"{BG_RED}{BWHT} ⚠ FAIL-OPEN ACTIVE {RST}"
        elif load == 1:
            status_icon = f"{BG_YEL}{BOLD} ▲ ELEVATED {RST}"
        else:
            status_icon = f"{BG_GRN}{BWHT} ● NORMAL {RST}"

        cpu_bar = f"CPU:{cpu_pct}%" if cpu_pct > 0 else ""
        queue_bar = f"Queue:{queue_pct}%" if queue_pct > 0 else ""
        detail = f"  {DIM}{cpu_bar} {queue_bar}{RST}" if cpu_bar or queue_bar else ""

        print(f"\n  {BOLD}System Status:{RST}  {status_icon}  {color}Load: {name}{RST}{detail}")

    def _draw_pending_alerts(self):
        """Draw alerts waiting for human decision — this is the CORE of Property 3."""
        pending = []

        if self.sim_mode:
            pending = self.sim_pending[:10]
        else:
            count = self.bridge.get_pending_count()
            for i in range(min(count, 10)):
                p = self.bridge.get_pending(i)
                if p:
                    pending.append(p)

        if not pending:
            print(f"\n  {DIM}╔══════════════════════════════════════════════════════╗{RST}")
            print(f"  {DIM}║{RST}  {BGRN}✓ No pending alerts — system operating normally{RST}     {DIM}║{RST}")
            print(f"  {DIM}╚══════════════════════════════════════════════════════╝{RST}")
            return

        print(f"\n  {BOLD}{BG_RED}{WHT} ⚠ PENDING ALERTS — Awaiting Your Decision ({len(pending)}) {RST}")
        print(f"  {DIM}┌─────┬──────────────┬──────────┬────────────┬──────────────────┐{RST}")
        print(f"  {DIM}│{RST} {BOLD}#  {RST} {DIM}│{RST} {BOLD}Alert ID    {RST} {DIM}│{RST} {BOLD}Source IP {RST} {DIM}│{RST} {BOLD}Score     {RST} {DIM}│{RST} {BOLD}Confidence       {RST} {DIM}│{RST}")
        print(f"  {DIM}├─────┼──────────────┼──────────┼────────────┼──────────────────┤{RST}")

        for i, p in enumerate(pending):
            if self.sim_mode:
                alert_id, src_ip, score, conf, decision = p
            else:
                alert_id, src_ip, score, conf, decision = p

            conf_name, conf_color = CONFIDENCE_NAMES.get(conf, ("?", WHT))
            score_color = RED if score >= 60 else YEL if score >= 30 else GRN

            print(f"  {DIM}│{RST} {BCYN}{i+1:<3}{RST} {DIM}│{RST} {alert_id:<12} {DIM}│{RST} {ip_str(src_ip):<9} {DIM}│{RST} {score_color}{score:>6.1f}{RST}   {DIM}│{RST} {conf_color}{conf_name:<16}{RST} {DIM}│{RST}")

        print(f"  {DIM}└─────┴──────────────┴──────────┴────────────┴──────────────────┘{RST}")
        print(f"  {DIM}Actions:{RST} {BRED}[#] Block{RST} {BYEL}[t#] Temp{RST} {BGRN}[w#] White{RST} {DIM}[i#] Ignore{RST} {BMAG}[e#] Escalate{RST}")

    def _draw_blocked_ips(self):
        """Show currently blocked IPs."""
        if self.sim_mode:
            blocked = self.sim_blocked
        else:
            blocked = set()  # In production: read from Rust engine

        if not blocked:
            print(f"\n  {DIM}Blocked IPs: (none){RST}")
            return

        ip_list = [ip_str(ip) for ip in sorted(blocked)]
        line = "  " + BOLD + "Blocked IPs: " + RST
        line += f"{RED}" + f"{RST}, {RED}".join(ip_list) + RST
        print(line)

    def _draw_stats(self):
        """Draw engine statistics summary."""
        if self.sim_mode:
            s = self.sim_stats
            print(f"\n  {BOLD}Engine Stats:{RST}")
            print(f"    Evaluated: {s['evaluated']}  Passed: {GRN}{s['passed']}{RST}  "
                  f"Alerted: {YEL}{s['alerted']}{RST}  Blocked: {RED}{s['blocked']}{RST}  "
                  f"RateLimited: {MAG}{s['rate_limited']}{RST}  "
                  f"FailOpen: {DIM}{s['fail_open_passes']}{RST}")
        else:
            print(f"\n  {BOLD}Engine Stats:{RST} (read from Rust engine)")

    def _draw_full_screen(self):
        """Draw the complete console display."""
        self._clear_screen()
        self._draw_header()
        self._draw_fail_open_status()
        self._draw_pending_alerts()
        self._draw_blocked_ips()
        self._draw_stats()
        print(f"\n  {DIM}─" * 55 + RST)
        print(f"  {BOLD}Action >{RST} ", end="", flush=True)

    # ── Command Processing ───────────────────────────────────

    def _process_command(self, cmd: str):
        cmd = cmd.strip().lower()
        if not cmd:
            return

        if cmd == "quit" or cmd == "exit" or cmd == "q":
            self.running = False
            return

        if cmd == "help" or cmd == "?":
            self._show_help()
            return

        if cmd == "stats":
            self._draw_stats()
            input(f"\n  {DIM}Press Enter to continue...{RST}")
            return

        if cmd == "refresh":
            return  # Just redraw

        # block <ip>
        if cmd.startswith("block "):
            ip_str_val = cmd[6:].strip()
            ip = ip_int(ip_str_val)
            if ip == 0:
                print(f"  {BRED}Invalid IP: {ip_str_val}{RST}")
                input(f"  {DIM}Press Enter...{RST}")
                return
            if self.sim_mode:
                self.sim_blocked.add(ip)
            else:
                self.bridge.block_ip(ip)
            print(f"  {BRED}✓ Blocked {ip_str(ip)} permanently{RST}")
            input(f"  {DIM}Press Enter...{RST}")
            return

        # unblock <ip>
        if cmd.startswith("unblock "):
            ip_str_val = cmd[8:].strip()
            ip = ip_int(ip_str_val)
            if ip == 0:
                print(f"  {BRED}Invalid IP: {ip_str_val}{RST}")
                input(f"  {DIM}Press Enter...{RST}")
                return
            if self.sim_mode:
                self.sim_blocked.discard(ip)
                self.sim_whitelisted.add(ip)
            else:
                self.bridge.unblock_ip(ip)
            print(f"  {BGRN}✓ Unblocked/Whitelisted {ip_str(ip)}{RST}")
            input(f"  {DIM}Press Enter...{RST}")
            return

        # Resolve pending alert: #, t#, w#, i#, e#
        decision = None
        index_str = cmd

        if cmd.startswith("t"):
            decision = 2  # BlockTemp
            index_str = cmd[1:]
        elif cmd.startswith("w"):
            decision = 3  # Whitelist
            index_str = cmd[1:]
        elif cmd.startswith("i"):
            decision = 4  # Ignore
            index_str = cmd[1:]
        elif cmd.startswith("e"):
            decision = 5  # Escalate
            index_str = cmd[1:]
        elif cmd.isdigit():
            decision = 1  # Block (default for bare number)

        if decision is not None and index_str.isdigit():
            index = int(index_str) - 1  # 0-based
            pending = self.sim_pending if self.sim_mode else []

            if not self.sim_mode:
                # Get from Rust engine
                count = self.bridge.get_pending_count()
                for i in range(min(count, 10)):
                    p = self.bridge.get_pending(i)
                    if p:
                        pending.append(p)

            if 0 <= index < len(pending):
                alert = pending[index]
                alert_id = alert[0]
                src_ip = alert[1]

                if self.sim_mode:
                    # Remove from pending
                    self.sim_pending.pop(index)
                    if decision == 1:  # Block
                        self.sim_blocked.add(src_ip)
                    elif decision == 3:  # Whitelist
                        self.sim_whitelisted.add(src_ip)
                else:
                    self.bridge.set_policy(alert_id, decision)

                dec_name = HUMAN_DECISION_NAMES.get(decision, "?")
                dec_color = RED if decision in (1, 2) else GRN if decision == 3 else YEL
                print(f"  {dec_color}✓ Decision: {dec_name} for Alert #{alert_id} (IP: {ip_str(src_ip)}){RST}")
                input(f"  {DIM}Press Enter...{RST}")
                return

        print(f"  {DIM}Unknown command: {cmd}. Type 'help' for commands.{RST}")
        input(f"  {DIM}Press Enter...{RST}")

    def _show_help(self):
        print(f"\n  {BOLD}═══ Semi-NIDS Console Commands ═══{RST}")
        print(f"  {BCYN}[#]{RST}       Block source IP of alert # permanently")
        print(f"  {BCYN}[t#]{RST}      Temporary block (5 minutes)")
        print(f"  {BCYN}[w#]{RST}      Whitelist source IP (never alert again)")
        print(f"  {BCYN}[i#]{RST}      Ignore this alert (no action)")
        print(f"  {BCYN}[e#]{RST}      Escalate alert to higher DEFCON level")
        print(f"  {BCYN}block <ip>{RST}  Manually block an IP address")
        print(f"  {BCYN}unblock <ip>{RST} Unblock/whitelist an IP address")
        print(f"  {BCYN}stats{RST}      Show detailed engine statistics")
        print(f"  {BCYN}refresh{RST}    Force screen refresh")
        print(f"  {BCYN}help{RST}       Show this help")
        print(f"  {BCYN}quit{RST}       Exit console")
        print(f"\n  {DIM}Property 1: Adaptive Dropping — system only blocks when{RST}")
        print(f"  {DIM}  confidence ≥ High AND score ≥ threshold. Low confidence{RST}")
        print(f"  {DIM}  threats appear here for YOUR decision.{RST}")
        print(f"  {DIM}Property 2: Fail-Open — if overloaded, clean traffic{RST}")
        print(f"  {DIM}  passes through. Only risky packets are analyzed.{RST}")
        print(f"  {DIM}Property 3: Interactive Control — you decide on alerts{RST}")
        print(f"  {DIM}  that the system cannot confidently auto-block.{RST}")
        input(f"\n  {DIM}Press Enter to continue...{RST}")

    # ── Simulation Mode ──────────────────────────────────────

    def _sim_generate_events(self):
        """Generate simulated events for demo without Rust DLL."""
        import random
        if random.random() < 0.15:  # 15% chance of new alert each second
            src_ips = [
                ip_int("192.168.1.100"), ip_int("10.0.0.55"),
                ip_int("172.16.0.200"), ip_int("192.168.1.77"),
                ip_int("10.10.10.10"),  ip_int("203.0.113.42"),
            ]
            src_ip = random.choice(src_ips)
            score = random.uniform(20.0, 75.0)
            conf = random.choice([2, 3])  # Medium or High
            alert_id = len(self.sim_pending) + 1 + int(time.time()) % 1000
            self.sim_pending.append((alert_id, src_ip, score, conf, 0))

            # Update stats
            self.sim_stats["evaluated"] += 1
            if score >= 60:
                self.sim_stats["blocked"] += 1
            elif score >= 40:
                self.sim_stats["rate_limited"] += 1
            elif score >= 20:
                self.sim_stats["alerted"] += 1
            else:
                self.sim_stats["passed"] += 1

        # Also simulate some normal traffic
        self.sim_stats["evaluated"] += random.randint(50, 500)
        self.sim_stats["passed"] += random.randint(45, 480)

    # ── Main Loop ────────────────────────────────────────────

    def run(self):
        """Main console loop — display + input."""
        if not self.init():
            print(f"{BRED}Failed to initialize Semi-NIDS engine.{RST}")
            return

        # Signal handler for Ctrl+C
        original_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, lambda s, f: None)  # Disable Ctrl+C during input

        maintenance_counter = 0

        while self.running:
            try:
                # Periodic maintenance (every 10 seconds)
                now = time.time()
                if now - self.last_maintenance >= 10.0:
                    if self.bridge.available:
                        self.bridge.maintenance()
                    self.last_maintenance = now

                # Simulation events
                if self.sim_mode:
                    self._sim_generate_events()

                # Draw full screen
                self._draw_full_screen()

                # Get user input (non-blocking via timeout would be ideal,
                # but simple input() works for a console)
                signal.signal(signal.SIGINT, original_sigint)
                try:
                    cmd = input()
                except KeyboardInterrupt:
                    print(f"\n  {DIM}Use 'quit' to exit.{RST}")
                    cmd = ""
                signal.signal(signal.SIGINT, lambda s, f: None)

                # Process command
                self._process_command(cmd)

            except EOFError:
                break
            except Exception as e:
                print(f"  {BRED}Error: {e}{RST}")
                time.sleep(1)

        signal.signal(signal.SIGINT, original_sigint)
        self.shutdown()


# ═══════════════════════════════════════════════════════════════
# Standalone test / demo mode
# ═══════════════════════════════════════════════════════════════

def demo_semi_nids_decisions():
    """Demonstrate the 3 Semi-NIDS properties with simulated scenarios."""
    print(f"\n{BOLD}{BG_BLU}{WHT} AEGIS Semi-NIDS — Decision Demonstration {RST}\n")

    scenarios = [
        ("Normal HTTP request",            0xC0A80A01, 0.0,   0, 0, "Pass"),
        ("Suspicious port scan (4444)",    0xC0A80A01, 25.0,  1, 1, "AlertOnly"),
        ("Brute force attempt",            0x0A000001, 45.0,  2, 1, "RateLimit"),
        ("Known exploit + high conf",      0x0A000002, 65.0,  3, 1, "Block"),
        ("Critical C2 beacon",             0x0A000003, 90.0,  4, 1, "Block+Preserve"),
        ("Suspicious but uncertain",       0xC0A80A64, 35.0,  2, 1, "PendingHuman"),
    ]

    print(f"  {BOLD}Property 1: Adaptive & Threshold-based Dropping{RST}")
    print(f"  {DIM}System blocks only when confidence ≥ High AND score ≥ threshold{RST}\n")

    for desc, src_ip, score, conf, flags, expected in scenarios:
        conf_name, conf_color = CONFIDENCE_NAMES.get(conf, ("?", WHT))
        dec_name, dec_color = DECISION_NAMES.get(
            {"Pass": 0, "AlertOnly": 1, "RateLimit": 2, "Block": 3,
             "Block+Preserve": 4, "PendingHuman": 5}.get(expected, 0), ("?", WHT))

        print(f"  {BWHT}•{RST} {desc}")
        print(f"    Source: {ip_str(src_ip)}  Score: {score:.0f}  "
              f"Confidence: {conf_color}{conf_name}{RST}")
        print(f"    → Decision: {dec_color}{BOLD}{dec_name}{RST}")

    print(f"\n  {BOLD}Property 2: Graceful Degradation (Fail-Open){RST}")
    print(f"  {DIM}If CPU > 85% or queue > 95% → pass clean traffic through{RST}")
    print(f"  {DIM}Only continue analyzing packets with risk_flags ≠ 0{RST}\n")

    print(f"  {BG_YEL}{BOLD} ▲ ELEVATED {RST}  CPU=75% → analyze only risky packets")
    print(f"  {BG_RED}{BWHT} ⚠ OVERLOADED {RST} CPU=90% → pass clean, analyze high-risk only")
    print(f"  {BG_RED}{BRED} ✖ CRITICAL {RST}  Queue full → complete fail-open")

    print(f"\n  {BOLD}Property 3: Interactive Control Loop{RST}")
    print(f"  {DIM}Medium-confidence alerts queue for human decision{RST}")
    print(f"  {DIM}Operator sees alert and chooses action in real-time{RST}\n")

    print(f"  {CYN}Pending: Score=35.0, Confidence=Medium, IP=192.168.10.100{RST}")
    print(f"  {BRED}[1] Block{RST}  {BYEL}[t1] Temp{RST}  {BGRN}[w1] Whitelist{RST}  {DIM}[i1] Ignore{RST}  {BMAG}[e1] Escalate{RST}")
    print()


# ═══════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        demo_semi_nids_decisions()
    else:
        console = SemiNidsConsole()
        console.run()
