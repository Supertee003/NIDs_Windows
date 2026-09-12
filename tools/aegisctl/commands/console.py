"""Interactive console/TUI for AEGIS NIDS control."""
from __future__ import annotations

import argparse
import os
import sys
import subprocess
import time
import json
from pathlib import Path
from datetime import datetime

from ..config import (
    REPO_ROOT, RULES_FILE, LOGS_DIR, PID_DIR, SUBSYSTEMS, COMPONENTS,
    NDJSON_LOG, ANOMALOUS_LOG
)
from ..utils import load_json, save_json, read_pid, is_process_running

# Optional imports
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    # Try to import bridge ctypes from shared directory
    # Suppress stdout warning during import
    import io
    import contextlib
    shared_paths = [
        REPO_ROOT / "shared",
        REPO_ROOT / "scripts" / "shared",
    ]
    for sp in shared_paths:
        if sp.exists():
            sys.path.insert(0, str(sp))
    with contextlib.redirect_stdout(io.StringIO()):
        import aegis_bridge_ctypes as bridge
    BRIDGE_AVAILABLE = True
except ImportError:
    BRIDGE_AVAILABLE = False


class Colors:
    RST = '\033[0m'
    BLD = '\033[1m'
    DIM = '\033[2m'
    RED = '\033[91m'
    GRN = '\033[92m'
    YEL = '\033[93m'
    BLU = '\033[94m'
    MAG = '\033[95m'
    CYN = '\033[96m'
    WHT = '\033[97m'
    BRED = '\033[91;1m'
    BGRN = '\033[92;1m'
    BYEL = '\033[93;1m'
    BBLU = '\033[94;1m'
    BCYN = '\033[96;1m'


DEFCON_COLORS = {1: Colors.BRED, 2: Colors.RED, 3: Colors.YEL, 4: Colors.BYEL, 5: Colors.BGRN}
DEFCON_LABELS = {
    1: "COCKED PISTOL", 2: "DOUBLE TAKE", 3: "ROUND HOUSE",
    4: "FAST PACE", 5: "FADE OUT"
}


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def show_header():
    defcon_level, defcon_label = get_defcon()
    if defcon_level:
        dc = DEFCON_COLORS.get(defcon_level, Colors.RST)
        defcon_str = f"{dc}DEFCON {defcon_level} -- {defcon_label}{Colors.RST}"
    else:
        defcon_str = f"{Colors.DIM}DEFCON N/A{Colors.RST}"
    print(f"\n  {Colors.BCYN}AEGIS NIDS{Colors.RST} Control Center  [{defcon_str}]")


def input_pause():
    input(f"\n  {Colors.DIM}Press Enter to continue...{Colors.RST}")


def get_defcon() -> tuple:
    """Get DEFCON level -- try Bridge IPC first, then fallback to log file."""
    if BRIDGE_AVAILABLE:
        try:
            rc = bridge.bridge_init()
            if rc == 0:
                level = bridge.get_defcon_level()
                label = bridge.get_defcon_label()
                bridge.bridge_shutdown()
                if level is not None:
                    return level, label
        except Exception:
            pass
    
    # Fallback to log file
    try:
        if ANOMALOUS_LOG.exists():
            with open(ANOMALOUS_LOG, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(max(0, f.seek(0, 2) - 8192))
                lines = f.readlines()
                for line in reversed(lines):
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            if 'defcon_level' in data:
                                return data['defcon_level'], DEFCON_LABELS.get(data['defcon_level'], "UNKNOWN")
                        except json.JSONDecodeError:
                            continue
    except Exception:
        pass
    return None, None


def get_subsystem_status(name: str) -> dict:
    pid = read_pid(name)
    if pid is not None and is_process_running(pid):
        return {"status": "RUNNING", "pid": pid}
    return {"status": "STOPPED", "pid": None}


def get_all_status() -> list:
    results = []
    for name in COMPONENTS:
        status = get_subsystem_status(name)
        results.append((name, status["status"] == "RUNNING", status["pid"]))
    return results


def show_status():
    clear_screen()
    show_header()
    print(f"\n  {Colors.BLD}SYSTEM STATUS{Colors.RST}")
    print(f"  {'=' * 50}")
    
    running = 0
    total = len(COMPONENTS)
    
    for name, config in COMPONENTS.items():
        status = get_subsystem_status(name)
        if status["status"] == "RUNNING":
            pid_str = f" (PID: {status['pid']})" if status["pid"] else ""
            print(f"  {Colors.BGRN}[RUNNING]{Colors.RST} {name.upper():<10} {config.get('language', '?'):<8}{pid_str}")
            running += 1
        else:
            print(f"  {Colors.RED}[STOPPED]{Colors.RST} {name.upper():<10} {config.get('language', '?'):<8}")
    
    print(f"\n  {running}/{total} subsystems running")


def show_health():
    clear_screen()
    show_header()
    print(f"\n  {Colors.BLD}HEALTH CHECK{Colors.RST}")
    print(f"  {'=' * 50}")
    
    for name, config in COMPONENTS.items():
        status = get_subsystem_status(name)
        if status["status"] == "RUNNING":
            print(f"  {Colors.BGRN}[OK]{Colors.RST} {name.upper()}")
        else:
            print(f"  {Colors.RED}[FAIL]{Colors.RST} {name.upper()}")


def show_bridge_status():
    """Show Bridge IPC status."""
    print(f'\n  {Colors.BLD}BRIDGE -- IPC STATUS{Colors.RST}')
    print(f"  {'=' * 55}")
    
    if not BRIDGE_AVAILABLE:
        print(f"  {Colors.BRED}[!]{Colors.RST} aegis_bridge_ctypes not available")
        return
    
    rc = bridge.bridge_init()
    if rc != 0:
        print(f"  {Colors.BRED}[!]{Colors.RST} Bridge init failed (rc={rc})")
        return
    
    try:
        defcon = bridge.get_defcon_level()
        label = bridge.get_defcon_label()
        desc = bridge.get_defcon_description()
        color = DEFCON_COLORS.get(defcon, Colors.RST)
        print(f'  DEFCON    : {color}{defcon} -- {label}{Colors.RST}')
        print(f'  Description: {desc}')
        
        # Get other stats
        rules = bridge.get_active_rules()
        print(f'  Active Rules: {rules}')
    except Exception as e:
        print(f"  {Colors.RED}[!]{Colors.RST} Error reading Bridge status: {e}")
    finally:
        bridge.bridge_shutdown()


def measure_ipc_throughput():
    """Measure IPC throughput."""
    if not BRIDGE_AVAILABLE:
        print(f"\n  {Colors.RED}[-]{Colors.RST} Bridge not available")
        return
    
    rc = bridge.bridge_init()
    if rc != 0:
        print(f"\n  {Colors.RED}[-]{Colors.RST} Bridge init failed")
        return
    
    print(f"\n  {Colors.CYN}[IPC]{Colors.RST} Measuring throughput (3s)...")
    try:
        count = 0
        start = time.perf_counter()
        end_time = start + 3.0
        while time.perf_counter() < end_time:
            rc = bridge.push_event(
                event_type=0, source_ip=0, dest_ip=0,
                source_port=0, dest_port=0, protocol=6,
                tier_result=1, rule_id=0, severity=0,
                payload_len=0, signature=b"test"
            )
            count += 1
        elapsed = time.perf_counter() - start
        throughput = count / elapsed
        print(f"  {Colors.BGRN}[OK]{Colors.RST} {count} events in {elapsed:.1f}s = {throughput:.0f} events/sec")
    except Exception as e:
        print(f"  {Colors.RED}[-]{Colors.RST} Error: {e}")
    finally:
        bridge.bridge_shutdown()


def run_realtime_dashboard():
    """Real-time dashboard with CPU/memory/DEFCON."""
    print(f"\n  {Colors.CYN}[DASHBOARD]{Colors.RST} Press Ctrl+C to exit\n")
    if PSUTIL_AVAILABLE:
        psutil.cpu_percent(interval=None)
    try:
        while True:
            now = datetime.now().strftime("%H:%M:%S")
            defcon_level, defcon_label = get_defcon()
            if defcon_level:
                dc = DEFCON_COLORS.get(defcon_level, Colors.RST)
                defcon_str = f"{dc}DEFCON {defcon_level} {defcon_label}{Colors.RST}"
            else:
                defcon_str = f"{Colors.DIM}DEFCON N/A{Colors.RST}"
            
            statuses = get_all_status()
            running = sum(1 for _, r, _ in statuses if r)
            
            cpu = psutil.cpu_percent(interval=0) if PSUTIL_AVAILABLE else 0
            mem = psutil.virtual_memory() if PSUTIL_AVAILABLE else None
            mem_pct = mem.percent if mem else 0
            
            # Build status line
            status_parts = []
            for name, is_running, pid in statuses:
                if is_running:
                    status_parts.append(f"{Colors.GRN}{name.upper()[:4]}{Colors.RST}")
                else:
                    status_parts.append(f"{Colors.RED}{name.upper()[:4]}{Colors.RST}")
            status_line = " ".join(status_parts)
            
            # Build bars
            cpu_bar = "█" * int(cpu / 5) + "░" * (20 - int(cpu / 5))
            mem_bar = "█" * int(mem_pct / 5) + "░" * (20 - int(mem_pct / 5))
            
            # Clear and draw
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"\n  {Colors.BCYN}AEGIS NIDS Real-Time Dashboard{Colors.RST}  [{Colors.DIM}{now}{Colors.RST}]")
            print(f"  {'=' * 60}")
            print(f"  {defcon_str}")
            print(f"  Subsystems: {status_line}  ({running}/5)")
            print(f"  CPU: [{cpu_bar}] {cpu:.1f}%")
            print(f"  MEM: [{mem_bar}] {mem_pct:.1f}%")
            print(f"\n  Press Ctrl+C to exit")
            
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n\n  {Colors.DIM}Dashboard stopped.{Colors.RST}")


def menu_rules():
    while True:
        clear_screen()
        show_header()
        rules_data = load_json(RULES_FILE) or {}
        rule_list = rules_data.get("nids_rules", [])
        
        print(f"\n  {Colors.BLD}RULE MANAGEMENT{Colors.RST}  ({len(rule_list)} rules)")
        print(f"  {'=' * 80}")
        print(f"  {'ID':<8} | {'Layer':<14} | {'Attack Name':<30} | {'Action':<8}")
        print(f"  {'-' * 80}")
        
        for r in rule_list[:20]:  # Show first 20
            if '_comment' in r:
                continue
            policy = r.get('action', 'Alert')
            if policy.upper() in ("BLOCK", "DROP"):
                policy_display = f"{Colors.RED}{policy}{Colors.RST}"
            else:
                policy_display = f"{Colors.BYEL}{policy}{Colors.RST}"
            print(f"  {r.get('rule_id', 'N/A'):<8} | {r.get('layer', '?'):<14} | {r.get('name', 'N/A'):<30} | {policy_display}")
        
        print(f"\n  {Colors.BLD}Options:{Colors.RST}")
        print(f"  {Colors.BGRN}L{Colors.RST} List all  {Colors.BGRN}V{Colors.RST} Validate  {Colors.BGRN}R{Colors.RST} Reload  {Colors.YEL}B{Colors.RST} Back")
        choice = input(f"\n  {Colors.BLD}Select (L/V/R/B): {Colors.RST}").strip().upper()
        
        if choice == 'L':
            print(f"\n  {Colors.CYN}[RULES]{Colors.RST} Listing all rules...")
            subprocess.run([sys.executable, "tools/aegisctl.py", "rules", "list"])
            input_pause()
        elif choice == 'V':
            print(f"\n  {Colors.CYN}[RULES]{Colors.RST} Validating rules...")
            subprocess.run([sys.executable, "tools/aegisctl.py", "rules", "validate"])
            input_pause()
        elif choice == 'R':
            print(f"\n  {Colors.CYN}[RULES]{Colors.RST} Reloading rules...")
            subprocess.run([sys.executable, "tools/aegisctl.py", "rules", "reload"])
            input_pause()
        elif choice == 'B':
            break


def menu_health():
    while True:
        clear_screen()
        show_header()
        
        running = 0
        for name, config in COMPONENTS.items():
            status = get_subsystem_status(name)
            if status["status"] == "RUNNING":
                print(f"  {Colors.BGRN}[OK]{Colors.RST} {name.upper()}")
                running += 1
            else:
                print(f"  {Colors.RED}[FAIL]{Colors.RST} {name.upper()}")
        
        print(f"\n  Health: {running}/{len(COMPONENTS)} subsystems")
        
        print(f"\n  {Colors.BLD}Options:{Colors.RST}")
        print(f"  {Colors.BGRN}R{Colors.RST} Refresh  {Colors.BGRN}B{Colors.RST} Bridge  {Colors.BGRN}D{Colors.RST} Dashboard  {Colors.YEL}X{Colors.RST} Back")
        choice = input(f"\n  {Colors.BLD}Select (R/B/D/X): {Colors.RST}").strip().upper()
        
        if choice == 'R':
            continue  # Refresh by looping
        elif choice == 'B':
            show_bridge_status()
            input_pause()
        elif choice == 'D':
            run_realtime_dashboard()
        elif choice == 'X':
            break


def main_menu():
    while True:
        clear_screen()
        show_header()
        
        running = sum(1 for name in COMPONENTS if get_subsystem_status(name)["status"] == "RUNNING")
        total = len(COMPONENTS)
        
        print(f"\n  {Colors.BLD}MAIN MENU{Colors.RST}  ({running}/{total} subsystems)")
        print(f"  {'=' * 50}")
        print(f"  {Colors.BGRN}1{Colors.RST}  Status          System status")
        print(f"  {Colors.BGRN}2{Colors.RST}  Health          Health check + Dashboard")
        print(f"  {Colors.BGRN}3{Colors.RST}  Rules           Rule management")
        print(f"  {Colors.BGRN}4{Colors.RST}  Start           Start subsystems")
        print(f"  {Colors.BGRN}5{Colors.RST}  Stop            Stop subsystems")
        print(f"  {Colors.BGRN}6{Colors.RST}  Logs            View logs")
        print(f"  {Colors.BGRN}7{Colors.RST}  Dashboard       Live dashboard")
        print(f"  {Colors.BGRN}8{Colors.RST}  Bridge          Bridge IPC status")
        print(f"  {Colors.BGRN}9{Colors.RST}  IPC Test        Measure IPC throughput")
        print(f"  {Colors.YEL}0{Colors.RST}  Exit")
        
        choice = input(f"\n  {Colors.BLD}Select (0-9): {Colors.RST}").strip()
        
        if choice == '1':
            show_status()
            input_pause()
        elif choice == '2':
            menu_health()
        elif choice == '3':
            menu_rules()
        elif choice == '4':
            print(f"\n  {Colors.CYN}[START]{Colors.RST} Starting subsystems...")
            subprocess.run([sys.executable, "tools/aegisctl.py", "start", "--all"])
            input_pause()
        elif choice == '5':
            print(f"\n  {Colors.RED}[STOP]{Colors.RST} Stopping subsystems...")
            subprocess.run([sys.executable, "tools/aegisctl.py", "stop", "--all"])
            input_pause()
        elif choice == '6':
            print(f"\n  {Colors.CYN}[LOGS]{Colors.RST} Opening logs...")
            subprocess.run([sys.executable, "tools/aegisctl.py", "logs", "tail", "-n", "20"])
            input_pause()
        elif choice == '7':
            run_realtime_dashboard()
        elif choice == '8':
            show_bridge_status()
            input_pause()
        elif choice == '9':
            measure_ipc_throughput()
            input_pause()
        elif choice == '0':
            break


def cmd_console(args: argparse.Namespace) -> int:
    """Launch interactive console/TUI."""
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {Colors.DIM}Exiting...{Colors.RST}")
    return 0


def setup_subcommands(sub) -> None:
    p = sub.add_parser("console", help="Interactive console/TUI")
    p.set_defaults(func=cmd_console)