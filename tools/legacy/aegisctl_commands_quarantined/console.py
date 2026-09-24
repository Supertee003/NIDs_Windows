"""Interactive console/TUI for AEGIS NIDS control."""
from __future__ import annotations

import argparse
import os
import sys
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
    # Fallback: try control API
    try:
        from aegisctl.api.control_api import get_defcon as ctrl_get_defcon
        return ctrl_get_defcon()
    except Exception:
        pass
    return None


def get_subsystem_status(name: str) -> dict:
    """Get subsystem status via control API."""
    try:
        from aegisctl.api.control_api import get_all_status
        statuses = get_all_status()
        for n, is_running, pid in statuses:
            if n == name:
                return {"status": "RUNNING" if is_running else "STOPPED", "pid": pid}
    except Exception:
        pass
    # Fallback: check PID file
    pid_file = Path(PID_DIR) / f"{name.lower()}.pid"
    if pid_file.exists():
        pid = int(pid_file.read_text().strip())
        try:
            import psutil
            p = psutil.Process(pid)
            if p.is_running():
                return {"status": "RUNNING", "pid": pid}
        except Exception:
            pass
    return {"status": "STOPPED", "pid": None}


def get_all_status() -> list:
    """Get all subsystem statuses via control API."""
    try:
        from aegisctl.api.control_api import get_all_status as ctrl_get
        return ctrl_get()
    except Exception:
        pass
    # Fallback: return empty
    return []


def load_rules() -> dict:
    """Load rules via control API."""
    try:
        from aegisctl.api.control_api import load_rules as ctrl_load
        return ctrl_load()
    except Exception:
        return {"nids_rules": []}


def compile_tier2_rules(rules_data: dict) -> list:
    """Compile tier-2 rules via control API."""
    try:
        from aegisctl.api.control_api import compile_tier2_rules as ctrl_compile
        return ctrl_compile(rules_data)
    except Exception:
        return []


def start_all_subsystems() -> None:
    """Start all subsystems via control API."""
    try:
        from aegisctl.api.control_api import start_all as ctrl_start
        ctrl_start()
    except Exception as e:
        print(f"  {Colors.RED}[!]{Colors.RST} Failed to start subsystems: {e}")


def stop_all_subsystems() -> None:
    """Stop all subsystems via control API."""
    try:
        from aegisctl.api.control_api import stop_all as ctrl_stop
        ctrl_stop()
    except Exception as e:
        print(f"  {Colors.RED}[!]{Colors.RST} Failed to stop subsystems: {e}")


def tail_logs(n: int = 20) -> None:
    """Tail logs via control API."""
    try:
        from aegisctl.api.control_api import tail_logs as ctrl_tail
        ctrl_tail(n=n)
    except Exception as e:
        print(f"  {Colors.RED}[!]{Colors.RST} Failed to tail logs: {e}")


def show_bridge_status():
    """Show bridge IPC status via control API."""
    from aegisctl.api.control_api import get_defcon, get_active_rules
    
    defcon = get_defcon()
    if defcon:
        print(f"\n  DEFCON: {defcon[0]} ({defcon[1]})")
    
    rules = get_active_rules()
    print(f"  Active Rules: {len(rules)} rules loaded")
    
    # Note: Bridge IPC is supplementary; primary authority is Rust PEP


def measure_ipc_throughput():
    """Measure IPC throughput via control API."""
    from aegisctl.api.control_api import get_all_status
    statuses = get_all_status()
    print(f"\n  IPC measurement (stats from control API)")
    print(f"  Subsystems: {len(statuses)}")


def show_status():
    """Show current system status."""
    clear_screen()
    show_header()
    
    statuses = get_all_status()
    running = sum(1 for _, r, _ in statuses if r)
    total = len(statuses)
    
    print(f"\n  {running}/{total} subsystems running")
    for name, is_running, pid in statuses:
        if is_running:
            print(f"  [RUNNING] {name.upper():<10} (PID: {pid})")
        else:
            print(f"  [STOPPED] {name.upper():<10}")
    
    input_pause()


def menu_rules():
    """Rule management menu."""
    while True:
        clear_screen()
        show_header()
        
        print(f"\n  {Colors.BLD}[RULES] Menu{Colors.RST}")
        print(f"  [1] List all rules")
        print(f"  [2] Validate rules")
        print(f"  [3] Reload rules")
        print(f"  [B] Back to main menu")
        
        choice = input(f"\n  {Colors.BLD}Select (1-3/B): {Colors.RST}").strip().upper()
        
        if choice == '1':
            print(f"\n  {Colors.CYN}[RULES]{Colors.RST} Listing all rules...")
            rules_data = load_rules()
            rule_list = rules_data.get("nids_rules", [])
            print(f"\n  Total rules: {len(rule_list)}")
            input_pause()
        elif choice == '2':
            print(f"\n  {Colors.CYN}[RULES]{Colors.RST} Validating rules...")
            from aegisctl.api.control_api import compile_tier2_rules
            rules_data = load_rules()
            compiled = compile_tier2_rules(rules_data)
            print(f"\n  Rules compiled: {len(compiled)}")
            input_pause()
        elif choice == '3':
            print(f"\n  {Colors.CYN}[RULES]{Colors.RST} Reloading rules...")
            from aegisctl.api.control_api import load_rules
            rules_data = load_rules()
            new_count = len(rules_data.get("nids_rules", []))
            print(f"\n  Rules reloaded: {new_count}")
            input_pause()
        elif choice == 'B':
            break
        else:
            print(f"  {Colors.RED}[!]{Colors.RST} Invalid choice")
            input_pause()


def menu_health():
    """Health check menu."""
    while True:
        clear_screen()
        show_header()
        
        # Use control_api to get status
        from aegisctl.api.control_api import get_all_status, get_defcon
        statuses = get_all_status()
        running = sum(1 for _, r, _ in statuses if r)
        total = len(statuses)
        print(f"\n  {running}/{total} subsystems running")
        for name, is_running, pid in statuses:
            if is_running:
                print(f"  [RUNNING] {name.upper():<10} (PID: {pid})")
            else:
                print(f"  [STOPPED] {name.upper():<10}")
        
        defcon = get_defcon()
        if defcon:
            print(f"\n  DEFCON: {defcon[0]} ({defcon[1]})")
        
        print(f"\n  {Colors.BLD}Options:{Colors.RST}")
        print(f"  [1] Refresh")
        print(f"  [2] Detailed status")
        print(f"  [3] Real-time dashboard")
        print(f"  [0] Main menu")
        
        choice = input(f"\n  {Colors.BLD}Select (0-3): {Colors.RST}").strip()
        
        if choice == '1':
            # Refresh - just re-read
            pass
        elif choice == '2':
            input_pause()
        elif choice == '3':
            run_realtime_dashboard()
        elif choice == '0':
            break


def run_realtime_dashboard():
    """Run real-time dashboard."""
    print(f"\n  {Colors.CYN}[DASHBOARD]{Colors.RST} Starting real-time dashboard...")
    # Placeholder - would start a live updating display
    input_pause()


def main_menu():
    """Main menu loop."""
    while True:
        clear_screen()
        show_header()
        
        # Use control_api to get status
        from aegisctl.api.control_api import get_all_status, get_defcon
        statuses = get_all_status()
        running = sum(1 for _, r, _ in statuses if r)
        total = len(statuses)
        
        defcon = get_defcon()
        
        print(f"\n  {Colors.BLD}MAIN MENU{Colors.RST}  ({running}/{total} subsystems)")
        print(f"  {'=' * 50}")
        if defcon:
            print(f"  DEFCON: {defcon[0]} ({defcon[1]})")
        print(f"  [1] Status          System status")
        print(f"  [2] Health          Health check + Dashboard")
        print(f"  [3] Rules           Rule management")
        print(f"  [4] Start           Start subsystems")
        print(f"  [5] Stop            Stop subsystems")
        print(f"  [6] Logs            View logs")
        print(f"  [7] Dashboard       Live dashboard")
        print(f"  [8] Bridge          Bridge IPC status")
        print(f"  [9] IPC Test        Measure IPC throughput")
        print(f"  {Colors.YEL}[0] Exit{Colors.RST}")
        
        choice = input(f"\n  {Colors.BLD}Select (0-9): {Colors.RST}").strip()
        
        if choice == '1':
            # Status already shown above
            input_pause()
        elif choice == '2':
            menu_health()
        elif choice == '3':
            menu_rules()
        elif choice == '4':
            print(f"\n  {Colors.CYN}[START]{Colors.RST} Starting subsystems...")
            from aegisctl.api.control_api import start_all_subsystems
            start_all_subsystems()
            input_pause()
        elif choice == '5':
            print(f"\n  {Colors.RED}[STOP]{Colors.RST} Stopping subsystems...")
            from aegisctl.api.control_api import stop_all_subsystems
            stop_all_subsystems()
            input_pause()
        elif choice == '6':
            print(f"\n  {Colors.CYN}[LOGS]{Colors.RST} Opening logs...")
            from aegisctl.api.control_api import tail_logs
            tail_logs(n=20)
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