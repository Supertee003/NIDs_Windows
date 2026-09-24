#!/usr/bin/env python3
"""Update console.py to use control_api instead of subprocess/bridge."""

import sys
import os

# Read original file
with open('tools/aegisctl/commands/console.py', 'r', encoding='utf-8') as f:
    data = f.read()

# 1. Replace the rules choice block
old_rules_block = """        if choice == 'L':
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
            break"""

new_rules_block = """        if choice == 'L':
            print(f"\n  {Colors.CYN}[RULES]{Colors.RST} Listing all rules...")
            from aegisctl.api.control_api import load_rules
            rules_data = load_rules()
            rule_list = rules_data.get("nids_rules", [])
            print(f"\n  Total rules: {len(rule_list)}")
            input_pause()
        elif choice == 'V':
            print(f"\n  {Colors.CYN}[RULES]{Colors.RST} Validating rules...")
            from aegisctl.api.control_api import compile_tier2_rules
            from aegisctl.api.control_api import load_rules
            rules_data = load_rules()
            compiled = compile_tier2_rules(rules_data)
            print(f"\n  Rules compiled: {len(compiled)}")
            input_pause()
        elif choice == 'R':
            print(f"\n  {Colors.CYN}[RULES]{Colors.RST} Reloading rules...")
            from aegisctl.api.control_api import load_rules
            rules_data = load_rules()
            new_count = len(rules_data.get("nids_rules", []))
            print(f"\n  Rules reloaded: {new_count}")
            input_pause()
        elif choice == 'B':
            break"""

data = data.replace(old_rules_block, new_rules_block)

# 2. Replace menu_health function
old_menu_health = """def menu_health():
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
        print(f"  {Colors.BGRN}R{Colors.RST} Refresh  {Colors.BGRN}B{Colors.RST} Bridge  {Colors.BGRN}D{Colors.RST} Dash")
        choice = input(f"\n  {Colors.BLD}Select (R/B/D/X): {Colors.RST}").strip()
        
        if choice == 'R':
            continue  # Refresh by looping
        elif choice == 'B':
            show_bridge_status()
            input_pause()
        elif choice == 'D':
            run_realtime_dashboard()
        elif choice == 'X':
            break"""

new_menu_health = """def menu_health():
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
            break"""

data = data.replace(old_menu_health, new_menu_health)

# 3. Replace main_menu function
old_main_menu = """def main_menu():
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
        print(f"  {Colors.YEL}[0] Exit{Colors.RST}")
        
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
            break"""

new_main_menu = """def main_menu():
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
            break"""

data = data.replace(old_main_menu, new_main_menu)

# Write updated file
with open('tools/aegisctl/commands/console.py', 'w', encoding='utf-8') as f:
    f.write(data)

print("console.py updated successfully")