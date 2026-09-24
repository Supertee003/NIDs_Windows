#!/usr/bin/env python3
"""Fix main_menu in console.py to use control_api."""

with open('tools/aegisctl/commands/console.py', 'r') as f:
    data = f.read()

# Replace the main menu choices (from choice = input onwards)
old_block = """        choice = input(f"\n  {Colors.BLD}Select (0-9): {Colors.RST}").strip()
        
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

new_block = """        choice = input(f"\n  {Colors.BLD}Select (0-9): {Colors.RST}").strip()
        
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

data = data.replace(old_block, new_block)

# Also replace the running/total calculation and menu header
old_running = """        running = sum(1 for name in COMPONENTS if get_subsystem_status(name)["status"] == "RUNNING")
        total = len(COMPONENTS)
        
        print(f"\n  {Colors.BLD}MAIN MENU{Colors.RST}  ({running}/{total} subsystems)")
        print(f"  {'=' * 50}"""

new_running = """        # Use control_api to get status
        from aegisctl.api.control_api import get_all_status, get_defcon
        statuses = get_all_status()
        running = sum(1 for _, r, _ in statuses if r)
        total = len(statuses)
        
        defcon_val = get_defcon()
        
        print(f"\n  {Colors.BLD}MAIN MENU{Colors.RST}  ({running}/{total} subsystems)")
        print(f"  {'=' * 50}")
        if defcon_val:
            print(f"  DEFCON: {defcon_val[0]} ({defcon_val[1]})""""

data = data.replace(old_running, new_running)

with open('tools/aegisctl/commands/console.py', 'w') as f:
    f.write(data)

print("Done fixing console.py")