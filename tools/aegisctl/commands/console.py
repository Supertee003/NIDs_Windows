"""Interactive console/TUI for AEGIS NIDS control."""
from __future__ import annotations

import argparse
import os
import sys
import subprocess
import time
from pathlib import Path

from ..config import (
    REPO_ROOT, RULES_FILE, LOGS_DIR, PID_DIR, SUBSYSTEMS, COMPONENTS
)
from ..utils import load_json, save_json, read_pid, is_process_running


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


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def show_header():
    print(f"\n  {Colors.BCYN}AEGIS NIDS{Colors.RST} Control Center")
    print(f"  {'=' * 60}")


def input_pause():
    input(f"\n  {Colors.DIM}Press Enter to continue...{Colors.RST}")


def get_subsystem_status(name: str) -> dict:
    pid = read_pid(name)
    if pid is not None and is_process_running(pid):
        return {"status": "RUNNING", "pid": pid}
    return {"status": "STOPPED", "pid": None}


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
        print(f"\n  {Colors.BLD}SYSTEM HEALTH{Colors.RST}")
        print(f"  {'=' * 50}")
        
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
        print(f"  {Colors.BGRN}R{Colors.RST} Refresh  {Colors.BGRN}S{Colors.RST} Status  {Colors.YEL}B{Colors.RST} Back")
        choice = input(f"\n  {Colors.BLD}Select (R/S/B): {Colors.RST}").strip().upper()
        
        if choice == 'R':
            continue  # Refresh by looping
        elif choice == 'S':
            show_status()
            input_pause()
        elif choice == 'B':
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
        print(f"  {Colors.BGRN}2{Colors.RST}  Health          Health check")
        print(f"  {Colors.BGRN}3{Colors.RST}  Rules           Rule management")
        print(f"  {Colors.BGRN}4{Colors.RST}  Start           Start subsystems")
        print(f"  {Colors.BGRN}5{Colors.RST}  Stop            Stop subsystems")
        print(f"  {Colors.BGRN}6{Colors.RST}  Logs            View logs")
        print(f"  {Colors.BGRN}7{Colors.RST}  Dashboard       Live dashboard")
        print(f"  {Colors.YEL}0{Colors.RST}  Exit")
        
        choice = input(f"\n  {Colors.BLD}Select (0-7): {Colors.RST}").strip()
        
        if choice == '1':
            show_status()
            input_pause()
        elif choice == '2':
            show_health()
            input_pause()
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
            print(f"\n  {Colors.CYN}[DASHBOARD]{Colors.RST} Launching dashboard...")
            subprocess.run([sys.executable, "tools/aegisctl.py", "dashboard"])
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