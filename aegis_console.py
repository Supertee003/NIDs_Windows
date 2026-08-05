"""
AEGIS NIDS — Console UI (v2 — Bridge Integration)
====================================================
Menu-driven launcher + rule management + threat graph viewer + Bridge status

Changes from v1:
  - Added Bridge status display (DEFCON, event count, subsystem health)
  - Added Bridge test option (run test_e2e.py)
  - Show 5-tuple info in rule display (target_ports, target_protocols)
  - Import aegis_bridge_ctypes for Bridge integration
"""
import os
import sys
import json
import subprocess
import webbrowser
import time

# Optional: aegis_graph requires networkx + pyvis
try:
    import aegis_graph
    AEGIS_GRAPH_AVAILABLE = True
except ImportError:
    AEGIS_GRAPH_AVAILABLE = False

# C++ IPC Bridge integration
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "bridge"))
try:
    import aegis_bridge_ctypes as bridge
    BRIDGE_AVAILABLE = True
except ImportError:
    BRIDGE_AVAILABLE = False

RULES_FILE = "Rules.json"
GRAPH_HTML_FILE = "threat_graph.html"


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def load_rules():
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "nids_rules" not in data:
                data["nids_rules"] = []
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        return {"nids_rules": []}


def save_rules(rules):
    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=4, ensure_ascii=False)


def show_bridge_status():
    """Show C++ IPC Bridge status — DEFCON, event count, subsystem health"""
    print("\n" + "=" * 60)
    print("  AEGIS BRIDGE — IPC Status")
    print("=" * 60)

    if not BRIDGE_AVAILABLE:
        print("  [!] aegis_bridge_ctypes not available — Bridge not loaded")
        print("  Run: cmake -B build && cmake --build build --config Release")
        return

    rc = bridge.bridge_init()
    if rc != 0:
        print(f"  [!] Bridge init failed (rc={rc}) — aegis_ipc.dll not found?")
        return

    try:
        # DEFCON level
        defcon = bridge.get_defcon_level()
        label = bridge.get_defcon_label()
        desc = bridge.get_defcon_description()

        defcon_colors = {1: '\033[91;1m', 2: '\033[91m', 3: '\033[93;1m', 4: '\033[93m', 5: '\033[92m'}
        color = defcon_colors.get(defcon, '\033[0m')
        reset = '\033[0m'

        print(f"  DEFCON Level : {color}{defcon} — {label}{reset}")
        print(f"  Description  : {desc}")

        # Event stats
        event_count = bridge.get_event_count()
        dropped = bridge.get_dropped_count()
        print(f"  Events Queue : {event_count}")
        print(f"  Dropped      : {dropped}")

        # Test push/pop
        rc = bridge.push_event(
            event_type=0, source_ip=0, dest_ip=0,
            source_port=0, dest_port=0, protocol=6,
            tier_result=1, rule_id=0, severity=0,
        )
        print(f"  Push Test    : {'OK' if rc == 0 else f'FAILED (rc={rc})'}")

        if rc == 0:
            event = bridge.pop_event()
            if event:
                print(f"  Pop Test     : OK (rule_id={event.rule_id}, tier={event.tier_result})")
            else:
                print(f"  Pop Test     : FAILED (no event returned)")

    finally:
        bridge.bridge_shutdown()

    print("=" * 60)


def manage_rules_ui():
    while True:
        clear_screen()
        rules = load_rules()

        print("=======================================================================")
        print("                 AEGIS NIDS - RULE MANAGEMENT UI                       ")
        print("=======================================================================")
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
                policy_display = f"\033[91;1m{policy}\033[0m"
            else:
                policy_display = f"\033[93;1m{policy}\033[0m"

            ports_str = ",".join(str(p) for p in target_ports) if target_ports else "*"
            proto_str = ",".join(target_protocols) if target_protocols else "*"

            print(f"{r.get('rule_id', 'N/A'):<8} | {layer:<14} | {r.get('name', 'N/A'):<32} | {policy_display:<17} | {ports_str:<12} | {proto_str}")

        print("\n[Options]")
        print("  [T]oggle Action  : Change defense policy")
        print("  [A]dd Rule       : Add new detection rule")
        print("  [D]elete Rule    : Remove a rule")
        print("  [B]ack           : Return to main menu")

        choice = input("\nSelect (T/A/D/B): ").strip().upper()

        if choice == 'T':
            target_id = input("Enter Rule ID to toggle (e.g., R0001): ").strip().upper()
            found = False
            for r in rules.get("nids_rules", []):
                if r.get("rule_id", "").upper() == target_id:
                    current = r.get("action", "Alert")
                    if current.upper() in ("BLOCK", "DROP"):
                        r["action"] = "Alert"
                    else:
                        r["action"] = "Block"
                    save_rules(rules)
                    print(f"\n[+] Rule {target_id} changed to '{r['action']}' successfully!")
                    found = True
                    break
            if not found:
                print(f"\n[-] Rule ID '{target_id}' not found")
            time.sleep(1.5)

        elif choice == 'A':
            new_id = input("New Rule ID (e.g., R0099): ").strip().upper()
            new_name = input("Rule Name: ").strip()
            new_regex = input("Regex Pattern: ").strip()
            new_action = input("Action (Alert/Block) [Alert]: ").strip()
            if not new_action:
                new_action = "Alert"

            # Optional: target_ports and target_protocols
            ports_input = input("Target Ports (comma-separated, e.g., 80,443 or * for all) [*]: ").strip()
            target_ports = []
            if ports_input and ports_input != "*":
                try:
                    target_ports = [int(p.strip()) for p in ports_input.split(",") if p.strip()]
                except ValueError:
                    pass

            proto_input = input("Target Protocols (comma-separated, e.g., TCP,UDP or * for all) [*]: ").strip().upper()
            target_protocols = []
            if proto_input and proto_input != "*":
                target_protocols = [p.strip() for p in proto_input.split(",") if p.strip()]

            # Auto-derive fast_pattern
            new_fast_pattern = "CUSTOM"
            if new_regex and len(new_regex) >= 3:
                fp = ""
                for c in new_regex:
                    if c.isalnum():
                        fp += c
                        if len(fp) >= 4:
                            break
                if len(fp) >= 3:
                    new_fast_pattern = fp

            new_rule = {
                "rule_id": new_id,
                "name": new_name,
                "match_pattern": "",
                "regex_pattern": new_regex,
                "severity": "High",
                "action": new_action,
            }
            if target_ports:
                new_rule["target_ports"] = target_ports
            if target_protocols:
                new_rule["target_protocols"] = target_protocols

            rules.setdefault("nids_rules", []).append(new_rule)
            save_rules(rules)
            print(f"\n[+] Rule {new_id} created successfully! System will auto-reload.")
            time.sleep(1.5)

        elif choice == 'D':
            target_id = input("Enter Rule ID to Delete (e.g., R0001): ").strip().upper()
            rules_list = rules.get("nids_rules", [])
            initial_count = len(rules_list)

            rules["nids_rules"] = [r for r in rules_list if r.get("rule_id", "").upper() != target_id]

            if len(rules["nids_rules"]) < initial_count:
                save_rules(rules)
                print(f"\n[+] Rule {target_id} deleted successfully!")
            else:
                print(f"\n[-] Rule ID '{target_id}' not found")
            time.sleep(1.5)

        elif choice == 'B':
            break

        else:
            print("\n[-] Invalid choice. Please try again.")
            time.sleep(1)


def main_menu():
    while True:
        clear_screen()

        # Show Bridge DEFCON in header
        defcon_str = ""
        if BRIDGE_AVAILABLE:
            try:
                rc = bridge.bridge_init()
                if rc == 0:
                    defcon = bridge.get_defcon_level()
                    label = bridge.get_defcon_label()
                    defcon_colors = {1: '\033[91;1m', 2: '\033[91m', 3: '\033[93;1m', 4: '\033[93m', 5: '\033[92m'}
                    color = defcon_colors.get(defcon, '\033[0m')
                    defcon_str = f" | DEFCON: {color}{defcon} {label}\033[0m"
                    bridge.bridge_shutdown()
            except Exception:
                pass

        print("========================================")
        print(f"      AEGIS NIDS - COMMAND CENTER{defcon_str}")
        print("========================================")
        print(" 1. [RUN]    Launch NIDS Subsystems")
        print(" 2. [RULES]  Manage Detection Rules")
        print(" 3. [LOGS]   Reset Anomalous Logs")
        print(" 4. [GRAPH]  Generate & View Threat Map")
        print(" 5. [BRIDGE] Bridge Status & Test")
        print(" 6. [TEST]   Run E2E Integration Test")
        print(" 7. [EXIT]   Shutdown Console")
        print("----------------------------------------")
        choice = input("Select Option (1-7): ").strip()

        if choice == '1':
            print("[!] Booting Zig Core, Brain, Bridge, and Sensors...")
            if os.name == 'nt':
                subprocess.Popen(
                    ["cmd", "/c", "start", "AEGIS Launcher", "run_aegis.bat"],
                    shell=True
                )
            else:
                # Linux/macOS fallback
                subprocess.Popen(
                    ["bash", "run_aegis.bat"],
                    cwd=os.path.dirname(os.path.abspath(__file__)) or "."
                )
            input("\nPress Enter to return...")

        elif choice == '2':
            manage_rules_ui()

        elif choice == '3':
            os.makedirs("logs", exist_ok=True)
            with open("logs/anomalous.json", "w") as f:
                pass  # truncate file
            print("[+] Logs cleared successfully.")
            input("\nPress Enter...")

        elif choice == '4':
            if not AEGIS_GRAPH_AVAILABLE:
                print("\n[-] Threat graph unavailable - missing dependencies.")
                print("    Install: pip install networkx pyvis")
                input("\nPress Enter to return...")
                continue
            print("\n[!] Generating Advanced Threat Analysis Graph...")
            try:
                aegis_graph.generate_threat_graph()
                html_path = os.path.abspath(GRAPH_HTML_FILE)
                if os.path.exists(html_path):
                    print(f"[+] Graph generated successfully!")
                    webbrowser.open(f"file:///{html_path}")
                else:
                    print(f"[-] Failed to find the generated map file: {html_path}")
            except Exception as e:
                print(f"[ERROR] Could not generate graph: {e}")
                print("Make sure you installed: pip install networkx pyvis")

            input("\nPress Enter to return...")

        elif choice == '5':
            show_bridge_status()
            input("\nPress Enter to return...")

        elif choice == '6':
            print("\n[!] Running E2E Integration Test...")
            try:
                result = subprocess.run(
                    [sys.executable, "test_e2e.py"],
                    capture_output=False,
                    text=True,
                    timeout=60,
                )
                if result.returncode == 0:
                    print("\n[+] All tests passed!")
                else:
                    print(f"\n[-] Some tests failed (exit code: {result.returncode})")
            except FileNotFoundError:
                print("[-] test_e2e.py not found")
            except subprocess.TimeoutExpired:
                print("[-] Test timed out (60s)")
            except Exception as e:
                print(f"[-] Error: {e}")
            input("\nPress Enter to return...")

        elif choice == '7':
            print("[!] Shutting down console...")
            break

        else:
            print("[-] Invalid choice.")
            time.sleep(1)


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n[!] Console stopped.")
