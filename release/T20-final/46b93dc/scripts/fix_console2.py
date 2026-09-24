#!/usr/bin/env python3
import sys

with open('tools/aegisctl/commands/console.py', 'r') as f:
    data = f.read()

# Fix the running/total calculation header
old_header = """        running = sum(1 for name in COMPONENTS if get_subsystem_status(name)["status"] == "RUNNING")
        total = len(COMPONENTS)
        
        print(f"\n  {Colors.BLD}MAIN MENU{Colors.RST}  ({running}/{total} subsystems)")"""
        
new_header = """        # Use control_api to get status
        from aegisctl.api.control_api import get_all_status, get_defcon
        statuses = get_all_status()
        running = sum(1 for _, r, _ in statuses if r)
        total = len(statuses)
        
        defcon_val = get_defcon()
        
        print(f"\n  {Colors.BLD}MAIN MENU{Colors.RST}  ({running}/{total} subsystems)")"""
        
data = data.replace(old_header, new_header)

# Fix the main menu choices
old_choices = """        if choice == '1':
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

new_choices = """        if choice == '1':
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

data = data.replace(old_choices, new_choices)

with open('tools/aegisctl/commands/console.py', 'w') as f:
    f.write(data)

print("Done fixing console.py")