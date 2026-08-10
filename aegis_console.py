#!/usr/bin/env python
"""
AEGIS NIDS — Interactive Console (v6 — Standalone TUI)
=======================================================
Interactive menu-driven UI for human operators.
Uses aegis_common for shared logic, calls aegis_daemon for background ops.

Key Design:
  - THIS IS THE INTERACTIVE UI — menus, colors, input prompts
  - aegis_daemon is the background CLI — no menus, no colors, no input
  - They share code via aegis_common.py
  - Console can call daemon via subprocess for start/stop operations
  - Or use aegis_common directly for status checks (faster, no subprocess)

Usage:
  python aegis_console.py          # interactive menu

Menu Options:
  1. [RUN]     Launch ALL via run_aegis.bat (original architecture)
  2. [MOUTH]   Mouth Control panel (start/stop/rebuild)
  3. [RULES]   Rule Management UI (add/toggle/delete)
  4. [LOGS]    Reset anomalous logs (with backup)
  5. [GRAPH]   Generate & view threat map
  6. [HEALTH]  System health + Bridge status
  7. [STATUS]  All subsystem status
  8. [TEST]    Run E2E integration test
  9. [DAEMON]  Call aegis_daemon commands directly
  0. [EXIT]    Shutdown console + optional stop all
"""
import os
import sys
import json
import subprocess
import webbrowser
import time
import shutil
from datetime import datetime

# Import shared library
try:
    import aegis_common as common
except ImportError:
    print("[FATAL] Cannot import aegis_common.py — must be in same directory")
    sys.exit(1)

# Enable VT100 on Windows
common.enable_windows_vt100()

# Optional: aegis_graph
try:
    import aegis_graph
    AEGIS_GRAPH_AVAILABLE = True
except ImportError:
    AEGIS_GRAPH_AVAILABLE = False

# C++ IPC Bridge integration
sys.path.insert(0, str(common.BASE_DIR / "bridge"))
try:
    import aegis_bridge_ctypes as bridge
    BRIDGE_AVAILABLE = True
except ImportError:
    BRIDGE_AVAILABLE = False

# =====================================================================
# ANSI COLORS
# =====================================================================
R = "\033[0m"
RED = "\033[91;1m"
GRN = "\033[92m"
YLW = "\033[93m"
CYN = "\033[96;1m"
MGN = "\033[95;1m"
DIM = "\033[2m"
BOLD = "\033[1m"


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


# =====================================================================
# HEADER HELPERS
# =====================================================================
def get_defcon_info():
    """Get DEFCON level from Bridge if available."""
    if not BRIDGE_AVAILABLE:
        return None, None, None
    try:
        rc = bridge.bridge_init()
        if rc != 0:
            return None, None, None
        level = bridge.get_defcon_level()
        label = bridge.get_defcon_label()
        bridge.bridge_shutdown()
        colors = {1: MGN, 2: RED, 3: YLW, 4: YLW, 5: GRN}
        return level, label, colors.get(level, R)
    except Exception:
        return None, None, None


def get_running_count():
    """Count running subsystems."""
    return sum(
        1 for sub in common.SUBSYSTEMS
        if common.is_process_running(sub["stop_pattern"])
    )


# =====================================================================
# MOUTH CONTROL PANEL (Option 2)
# =====================================================================
def mouth_control_ui():
    while True:
        clear()
        exe_exists = (common.BASE_DIR / common.MOUTH_EXE).exists()
        is_running = common.is_process_running(common.MOUTH_EXE)
        stale = common.needs_rebuild(common.MOUTH_SRC, common.MOUTH_EXE) if exe_exists else False

        print("=" * 55)
        print(f"  {RED}AEGIS MOUTH (Rust){R} — DEFCON Security Monitor")
        print("=" * 55)

        if is_running:
            print(f"  Status    : {GRN}RUNNING{R}")
        else:
            print(f"  Status    : {RED}STOPPED{R}")

        if exe_exists:
            if stale:
                print(f"  Binary    : {YLW}STALE{R} (source newer — rebuild recommended)")
            else:
                print(f"  Binary    : {GRN}UP-TO-DATE{R} ({common.MOUTH_EXE})")
        else:
            print(f"  Binary    : {RED}NOT BUILT{R}")

        print(f"  Source    : {common.MOUTH_SRC}")
        print("-" * 55)
        print(f"\n  [1] Start Mouth")
        print(f"  [2] Stop Mouth")
        print(f"  [3] Rebuild Mouth")
        print(f"  [4] Rebuild + Start")
        print(f"  [5] Back")

        choice = input("\n  Select (1-5): ").strip()

        if choice == '1':
            _mouth_start()
        elif choice == '2':
            _mouth_stop()
        elif choice == '3':
            _mouth_rebuild()
        elif choice == '4':
            _mouth_rebuild_start()
        elif choice == '5':
            break


def _mouth_start():
    print()
    exe_path = common.BASE_DIR / common.MOUTH_EXE
    if not exe_path.exists():
        print(f"  {RED}[!]{R} Not built — building first...")
        if not common.build_mouth_exe(verbose=True):
            input("\n  Press Enter...")
            return
    elif common.needs_rebuild(common.MOUTH_SRC, common.MOUTH_EXE):
        print(f"  {YLW}[!]{R} Source newer — auto-rebuilding...")
        if not common.build_mouth_exe(force=True):
            input("\n  Press Enter...")
            return

    if common.is_process_running(common.MOUTH_EXE, use_cache=False):
        print(f"  {YLW}[!]{R} Already running")
    else:
        CREATE_NEW_CONSOLE = 0x00000010
        subprocess.Popen(
            ["cmd", "/k", str(exe_path)],
            cwd=str(common.BASE_DIR),
            creationflags=CREATE_NEW_CONSOLE,
        )
        time.sleep(0.5)
        if common.is_process_running(common.MOUTH_EXE, use_cache=False):
            print(f"  {GRN}[OK]{R} Mouth launched!")
        else:
            print(f"  {YLW}[?]{R} Process started")
    input("\n  Press Enter...")


def _mouth_stop():
    print()
    common.stop_process(common.MOUTH_EXE)
    time.sleep(0.5)
    if not common.is_process_running(common.MOUTH_EXE, use_cache=False):
        print(f"  {GRN}[OK]{R} Mouth stopped")
    else:
        print(f"  {YLW}[!]{R} May still be shutting down")
    input("\n  Press Enter...")


def _mouth_rebuild():
    print()
    exe_path = common.BASE_DIR / common.MOUTH_EXE
    if exe_path.exists():
        try:
            exe_path.unlink()
        except PermissionError:
            print(f"  {YLW}[!]{R} Cannot remove — Mouth may be running. Stop first.")
            input("\n  Press Enter...")
            return
    common.build_mouth_exe(verbose=True)
    input("\n  Press Enter...")


def _mouth_rebuild_start():
    print()
    exe_path = common.BASE_DIR / common.MOUTH_EXE
    if common.is_process_running(common.MOUTH_EXE, use_cache=False):
        common.stop_process(common.MOUTH_EXE)
        time.sleep(0.5)
    if exe_path.exists():
        try:
            exe_path.unlink()
        except PermissionError:
            print(f"  {YLW}[!]{R} Cannot remove — stop Mouth manually first")
            input("\n  Press Enter...")
            return
    if common.build_mouth_exe(verbose=True):
        CREATE_NEW_CONSOLE = 0x00000010
        subprocess.Popen(
            ["cmd", "/k", str(exe_path)],
            cwd=str(common.BASE_DIR),
            creationflags=CREATE_NEW_CONSOLE,
        )
        time.sleep(0.5)
        if common.is_process_running(common.MOUTH_EXE, use_cache=False):
            print(f"  {GRN}[OK]{R} Mouth rebuilt + running!")
        else:
            print(f"  {YLW}[?]{R} Process started")
    input("\n  Press Enter...")


# =====================================================================
# RULE MANAGEMENT UI (Option 3)
# =====================================================================
def manage_rules_ui():
    while True:
        clear()
        rules = common.load_rules()
        print("=" * 100)
        print("                 AEGIS NIDS - RULE MANAGEMENT UI")
        print("=" * 100)
        print(f"{'ID':<8} | {'Layer':<14} | {'Attack Name':<32} | {'Policy':<8} | {'Ports':<12} | {'Proto'}")
        print("-" * 100)

        for r in rules.get("nids_rules", []):
            if '_comment' in r:
                continue
            policy = r.get('action', 'Alert')
            layer = r.get('layer', '?')
            target_ports = r.get('target_ports', [])
            target_protocols = r.get('target_protocols', [])

            if policy.upper() in ("BLOCK", "DROP"):
                policy_display = f"{RED}{policy}{R}"
            else:
                policy_display = f"{YLW}{policy}{R}"

            ports_str = ",".join(str(p) for p in target_ports) if target_ports else "*"
            proto_str = ",".join(target_protocols) if target_protocols else "*"

            print(f"{r.get('rule_id', 'N/A'):<8} | {layer:<14} | {r.get('name', 'N/A'):<32} | {policy_display:<17} | {ports_str:<12} | {proto_str}")

        print("\n[Options]")
        print("  [T]oggle Action  : Switch defense action")
        print("  [A]dd Rule       : Add new detection rule")
        print("  [D]elete Rule    : Delete existing rule")
        print("  [B]ack           : Back to main menu")

        choice = input("\nSelect action (T/A/D/B): ").strip().upper()

        if choice == 'T':
            target_id = input("Enter Rule ID: ").strip().upper()
            found = False
            for r in rules.get("nids_rules", []):
                if r.get("rule_id", "").upper() == target_id:
                    current = r.get("action", "Alert")
                    r["action"] = "Block" if current.upper() not in ("BLOCK", "DROP") else "Alert"
                    common.save_rules(rules)
                    print(f"\n{GRN}[+]{R} Rule {target_id} -> '{r['action']}'")
                    found = True
                    break
            if not found:
                print(f"\n{RED}[-]{R} Rule '{target_id}' not found")
            time.sleep(1.5)

        elif choice == 'A':
            print("\n--- Add New Rule ---")
            new_id = input("Rule ID (e.g., R0200): ").strip().upper()
            new_name = input("Attack Name: ").strip()
            new_regex = input("Regex Pattern (e.g., SELECT.*FROM): ").strip()
            new_layer = input("Layer [NETWORK]: ").strip().upper() or "NETWORK"
            action_input = input("Action (1=Alert, 2=Block, 3=Drop) [1]: ").strip()
            new_action = {"2": "Block", "3": "Drop"}.get(action_input, "Alert")

            new_fast_pattern = "CUSTOM"
            if new_regex and len(new_regex) >= 3:
                fp = "".join(c for c in new_regex if c.isalnum())[:4]
                if len(fp) >= 3:
                    new_fast_pattern = fp

            new_rule = {
                "rule_id": new_id, "name": new_name, "category": "Custom Rule",
                "layer": new_layer, "fast_pattern": new_fast_pattern,
                "match_pattern": "", "regex_pattern": new_regex,
                "severity": "High", "action": new_action,
            }
            rules.setdefault("nids_rules", []).append(new_rule)
            common.save_rules(rules)
            print(f"\n{GRN}[+]{R} Rule {new_id} created!")
            time.sleep(1.5)

        elif choice == 'D':
            target_id = input("Enter Rule ID to Delete: ").strip().upper()
            rules_list = rules.get("nids_rules", [])
            initial_count = len(rules_list)
            rules["nids_rules"] = [r for r in rules_list if r.get("rule_id", "").upper() != target_id]
            if len(rules["nids_rules"]) < initial_count:
                common.save_rules(rules)
                print(f"\n{GRN}[+]{R} Deleted {target_id}")
            else:
                print(f"\n{RED}[-]{R} Not found")
            time.sleep(1.5)

        elif choice == 'B':
            break
        else:
            print("\n[-] Invalid choice.")
            time.sleep(1)


# =====================================================================
# SYSTEM HEALTH (Option 6)
# =====================================================================
def show_health():
    """Show system health: subsystems, CPU, memory, Bridge, threats."""
    print("\n" + "=" * 60)
    print(f"  {CYN}AEGIS NIDS — System Health{R}")
    print("=" * 60)

    # Subsystem status
    print(f"\n  {BOLD}Subsystems:{R}")
    for sub in common.SUBSYSTEMS:
        is_running = common.is_process_running(sub["stop_pattern"])
        if is_running:
            print(f"    {GRN}{sub['name']:<10}{R} {GRN}RUNNING{R}")
        else:
            print(f"    {RED}{sub['name']:<10}{R} {RED}STOPPED{R}")

    # System resources
    if common.PSUTIL_AVAILABLE:
        import psutil
        print(f"\n  {BOLD}System Resources:{R}")
        try:
            print(f"    CPU Usage  : {psutil.cpu_percent(interval=0.5):.1f}%")
            mem = psutil.virtual_memory()
            print(f"    Memory     : {mem.percent:.1f}% ({mem.used / 1024**3:.1f} GB / {mem.total / 1024**3:.1f} GB)")
            disk_path = "C:\\" if os.name == 'nt' else "/"
            disk = psutil.disk_usage(disk_path)
            print(f"    Disk       : {disk.percent:.1f}% used")
        except Exception as e:
            print(f"    {YLW}[!]{R} Could not read: {e}")

    # Bridge IPC
    if BRIDGE_AVAILABLE:
        print(f"\n  {BOLD}Bridge IPC:{R}")
        try:
            rc = bridge.bridge_init()
            if rc == 0:
                defcon = bridge.get_defcon_level()
                label = bridge.get_defcon_label()
                colors = {1: MGN, 2: RED, 3: YLW, 4: YLW, 5: GRN}
                color = colors.get(defcon, R)
                print(f"    DEFCON     : {color}{defcon} {label}{R}")
                print(f"    Events     : {bridge.get_event_count()}")
                print(f"    Dropped    : {bridge.get_dropped_count()}")
                bridge.bridge_shutdown()
            else:
                print(f"    {RED}[!]{R} Bridge init failed (rc={rc})")
        except Exception as e:
            print(f"    {YLW}[!]{R} Bridge error: {e}")
    else:
        print(f"\n  {DIM}Bridge IPC: not available{R}")

    # Threat log
    if common.LOG_FILE.exists():
        try:
            with open(common.LOG_FILE, "r", encoding="utf-8") as f:
                lines = [l for l in f.readlines() if l.strip()]
            blocks = sum(1 for l in lines if '"Block"' in l or '"Drop"' in l)
            print(f"\n  {BOLD}Threat Log:{R}")
            print(f"    Total alerts : {len(lines)}")
            print(f"    Blocks/Drops : {blocks}")
        except Exception:
            pass

    print("\n" + "=" * 60)


# =====================================================================
# ALL SUBSYSTEM STATUS (Option 7)
# =====================================================================
def show_all_status():
    print("\n" + "=" * 65)
    print(f"  {CYN}AEGIS NIDS — Subsystem Status{R}")
    print("=" * 65)
    print(f"  {'#':<3} {'SUBSYSTEM':<10} {'STATUS':<12} {'PID':<8} {'CPU':<7} {'MEM':<8} {'PROCESS'}")
    print(f"  {'-'*65}")

    running_count = 0
    for i, sub in enumerate(common.SUBSYSTEMS, 1):
        pid = common.read_pid(sub["key"])
        is_running = common.is_process_running(sub["stop_pattern"])

        if is_running:
            status_str = f"{GRN}RUNNING{R}"
            running_count += 1
        else:
            status_str = f"{RED}STOPPED{R}"

        pid_str = str(pid) if pid else "-"
        if is_running and pid:
            cpu, mem = common.get_process_cpu_mem(pid)
            cpu_str = f"{cpu:.1f}%" if cpu is not None else "-"
            mem_str = f"{mem:.1f}M" if mem is not None else "-"
        else:
            cpu_str = "-"
            mem_str = "-"

        colors = {"Bridge": CYN, "Core": GRN, "Brain": YLW, "Nose": CYN, "Mouth": RED}
        name_color = colors.get(sub["name"], R)
        print(f"  {i:<3} {name_color}{sub['name']:<10}{R} {status_str:<20} {pid_str:<8} {cpu_str:<7} {mem_str:<8} {sub['stop_pattern']}")

    # Mouth binary info
    exe_exists = (common.BASE_DIR / common.MOUTH_EXE).exists()
    stale = common.needs_rebuild(common.MOUTH_SRC, common.MOUTH_EXE) if exe_exists else False
    if exe_exists:
        if stale:
            print(f"\n  Mouth binary: {YLW}STALE (rebuild recommended){R}")
        else:
            print(f"\n  Mouth binary: {GRN}UP-TO-DATE{R}")
    else:
        print(f"\n  Mouth binary: {RED}NOT BUILT{R}")

    # Timestamps
    src_path = common.BASE_DIR / common.MOUTH_SRC
    exe_path = common.BASE_DIR / common.MOUTH_EXE
    if src_path.exists():
        t = datetime.fromtimestamp(src_path.stat().st_mtime).strftime("%H:%M:%S")
        print(f"  Source time : {t}")
    if exe_path.exists():
        t = datetime.fromtimestamp(exe_path.stat().st_mtime).strftime("%H:%M:%S")
        print(f"  Binary time : {t}")

    # Log entries
    if common.LOG_FILE.exists():
        try:
            with open(common.LOG_FILE, "r", encoding="utf-8") as f:
                lines = [l for l in f.readlines() if l.strip()]
            print(f"  Log entries : {len(lines)} threats")
        except Exception:
            pass

    print(f"\n  {running_count}/{len(common.SUBSYSTEMS)} subsystems running")
    print("=" * 65)


# =====================================================================
# DAEMON BRIDGE (Option 9) — call aegis_daemon from console
# =====================================================================
DAEMON_COMMANDS = ["start", "stop", "restart", "status", "health", "rules", "logs", "watchdog", "build", "mouth"]


def daemon_bridge_ui():
    """Interactive wrapper to call aegis_daemon commands."""
    while True:
        clear()
        print("=" * 55)
        print(f"  {CYN}AEGIS DAEMON — Command Bridge{R}")
        print("=" * 55)
        print("  Call aegis_daemon.py commands from the console.")
        print("  Output is plain text (no colors).")
        print("-" * 55)
        print(f"\n  [1] start     — Start all subsystems (background)")
        print(f"  [2] stop      — Stop all subsystems")
        print(f"  [3] restart   — Restart all subsystems")
        print(f"  [4] status    — Show daemon status")
        print(f"  [5] health    — System health check")
        print(f"  [6] rules     — Hot-reload Rules.json")
        print(f"  [7] build     — Build all binaries")
        print(f"  [8] mouth     — Build Mouth binary")
        print(f"  [9] Back")

        choice = input("\n  Select (1-9): ").strip()
        cmd_map = {
            "1": "start", "2": "stop", "3": "restart",
            "4": "status", "5": "health", "6": "rules",
            "7": "build", "8": "mouth",
        }

        if choice == '9':
            break
        elif choice in cmd_map:
            cmd = cmd_map[choice]
            print(f"\n  {CYN}[DAEMON]{R} python aegis_daemon.py {cmd}\n")
            try:
                result = subprocess.run(
                    [sys.executable, "aegis_daemon.py", cmd],
                    cwd=str(common.BASE_DIR),
                    text=True,
                    timeout=30 if cmd not in ("logs", "watchdog") else None,
                )
                if result.returncode != 0:
                    print(f"\n  {RED}[!]{R} Exit code: {result.returncode}")
            except subprocess.TimeoutExpired:
                print(f"\n  {YLW}[!]{R} Command timed out (use Ctrl+C to cancel)")
            except FileNotFoundError:
                print(f"\n  {RED}[!]{R} aegis_daemon.py not found")
            except Exception as e:
                print(f"\n  {RED}[!]{R} Error: {e}")
            input("\n  Press Enter...")
        else:
            print(f"  {YLW}[!]{R} Invalid choice")
            time.sleep(1)


# =====================================================================
# GRACEFUL SHUTDOWN
# =====================================================================
def graceful_shutdown():
    """Stop all AEGIS subsystems."""
    print(f"\n{CYN}[SHUTDOWN]{R} Stopping all AEGIS subsystems...")
    stopped = 0
    for sub in common.SUBSYSTEMS:
        proc_name = sub["stop_pattern"]
        if common.is_process_running(proc_name, use_cache=False):
            print(f"  Stopping {sub['name']} ({proc_name})...")
            common.stop_process(proc_name)
            time.sleep(0.3)
            if not common.is_process_running(proc_name, use_cache=False):
                print(f"    {GRN}[OK]{R} Stopped")
                stopped += 1
            else:
                print(f"    {YLW}[!]{R} May still be running")
        else:
            print(f"  {sub['name']}: not running")
    print(f"\n  {GRN}Stopped {stopped} subsystems.{R}")


# =====================================================================
# MAIN MENU
# =====================================================================
def main_menu():
    while True:
        clear()

        # Header
        header_parts = []
        defcon, label, dcolor = get_defcon_info()
        if defcon is not None:
            header_parts.append(f"DEFCON: {dcolor}{defcon} {label}{R}")

        mouth_on = common.is_process_running(common.MOUTH_EXE)
        header_parts.append(f"Mouth: {GRN + 'ON' + R if mouth_on else RED + 'OFF' + R}")

        running = get_running_count()
        header_parts.append(f"Active: {running}/{len(common.SUBSYSTEMS)}")

        header_str = " | ".join(header_parts)

        print("=" * 55)
        print(f"     {BOLD}AEGIS NIDS — COMMAND CENTER (v6){R}")
        print(f"     {header_str}")
        print("=" * 55)
        print(f" {CYN}1{R}. [RUN]    Launch ALL via run_aegis.bat")
        print(f" {CYN}2{R}. [MOUTH]  Mouth Control (Start/Stop/Rebuild)")
        print(f" {CYN}3{R}. [RULES]  Manage Detection Rules")
        print(f" {CYN}4{R}. [LOGS]   Reset Anomalous Logs (with backup)")
        print(f" {CYN}5{R}. [GRAPH]  Generate & View Threat Map")
        print(f" {CYN}6{R}. [HEALTH] System Health & Bridge Status")
        print(f" {CYN}7{R}. [STATUS] All Subsystem Status")
        print(f" {CYN}8{R}. [TEST]   Run E2E Integration Test")
        print(f" {CYN}9{R}. [DAEMON] Call aegis_daemon Commands")
        print(f" {RED}0{R}. [EXIT]   Shutdown Console + Stop All?")
        print("-" * 55)
        choice = input("Select Option (0-9): ").strip()

        if choice == '1':
            # Launch via run_aegis.bat (original architecture)
            print(f"\n{CYN}[Pre-build]{R} Ensuring Mouth binary is up-to-date...")
            common.build_mouth_exe(verbose=True)

            print(f"\n{BOLD}[LAUNCH]{R} Starting AEGIS NIDS via run_aegis.bat...")
            bat_path = common.BASE_DIR / "run_aegis.bat"
            if os.name == 'nt':
                # os.startfile = double-click the .bat file in Explorer
                # This is the most reliable way on Windows:
                #   - Properly inherits desktop/console environment
                #   - 'start' commands inside the bat work correctly
                #   - Each subsystem gets its own visible window
                #   - No CREATE_NEW_CONSOLE issues with nested console creation
                os.startfile(str(bat_path))
            else:
                subprocess.Popen(["bash", "run_aegis.bat"], cwd=str(common.BASE_DIR))
            print(f"  {GRN}[OK]{R} Launcher window opened — check for 6 AEGIS windows")
            print(f"  {CYN}Tip:{R} If windows don't appear, try running run_aegis.bat directly")
            input(f"\n  Press Enter to return...")

        elif choice == '2':
            mouth_control_ui()

        elif choice == '3':
            manage_rules_ui()

        elif choice == '4':
            # Reset logs with backup
            log_path = common.LOG_FILE
            bak_path = common.LOGS_DIR / "anomalous.json.bak"
            common.ensure_dirs()

            if log_path.exists():
                try:
                    with open(log_path, "r", encoding="utf-8") as f:
                        content = f.read().strip()
                    if content:
                        shutil.copy2(log_path, bak_path)
                        count = len([l for l in content.split('\n') if l.strip()])
                        print(f"  {CYN}[BACKUP]{R} Saved {count} entries to anomalous.json.bak")
                    else:
                        print(f"  {DIM}[INFO]{R} Log file is already empty")
                except Exception as e:
                    print(f"  {YLW}[!]{R} Backup failed: {e}")

            with open(log_path, "w", encoding="utf-8") as f:
                pass
            print(f"  {GRN}[+]{R} Logs cleared.")
            input("\nPress Enter...")

        elif choice == '5':
            if not AEGIS_GRAPH_AVAILABLE:
                print(f"\n{RED}[-]{R} Threat graph unavailable. pip install networkx pyvis")
                input("\nPress Enter...")
                continue
            print(f"\n{CYN}[!]{R} Generating Threat Graph...")
            try:
                aegis_graph.generate_threat_graph()
                html_path = common.BASE_DIR / "threat_graph.html"
                if html_path.exists():
                    print(f"{GRN}[+]{R} Graph generated!")
                    webbrowser.open(f"file:///{html_path}")
            except Exception as e:
                print(f"{RED}[ERROR]{R} {e}")
            input("\nPress Enter...")

        elif choice == '6':
            show_health()
            input("\nPress Enter...")

        elif choice == '7':
            show_all_status()
            input("\nPress Enter...")

        elif choice == '8':
            print(f"\n{CYN}[!]{R} Running E2E Test...")
            try:
                result = subprocess.run(
                    [sys.executable, "test_e2e.py"],
                    capture_output=False, text=True, timeout=60,
                )
                if result.returncode == 0:
                    print(f"\n{GRN}[+]{R} All tests passed!")
                else:
                    print(f"\n{RED}[-]{R} Failed (exit {result.returncode})")
            except FileNotFoundError:
                print(f"{RED}[-]{R} test_e2e.py not found")
            except subprocess.TimeoutExpired:
                print(f"{RED}[-]{R} Timed out (60s)")
            except Exception as e:
                print(f"{RED}[-]{R} {e}")
            input("\nPress Enter...")

        elif choice == '9':
            daemon_bridge_ui()

        elif choice == '0':
            confirm = input(f"\n  {YLW}Stop all subsystems and exit? (y/N): {R}").strip().lower()
            if confirm == 'y':
                graceful_shutdown()
                print(f"\n  {CYN}AEGIS Console closed.{R}")
                break
            else:
                print(f"  {DIM}Exit cancelled.{R}")
                time.sleep(1)

        else:
            print("[-] Invalid choice.")
            time.sleep(1)


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{YLW}[!]{R} Console interrupted.")
