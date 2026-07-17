"""
AEGIS NIDS — Console UI
=======================
Menu-driven launcher + rule management + threat graph viewer

Fixes from previous version:
  - Use rules.get('nids_rules', []) everywhere (KeyError-safe)
  - Fix filename mismatch: aegis_threat_map.html -> threat_graph.html
  - Re-enable toggle action feedback (was commented out)
  - Set dict default before append to prevent KeyError on add rule
"""
import os
import json
import subprocess
import webbrowser
import time

import aegis_graph

# แก้ไขให้ชื่อไฟล์ตรงกับเครื่องยนต์หลัก (ตัว R พิมพ์ใหญ่)
RULES_FILE = "Rules.json"
GRAPH_HTML_FILE = "threat_graph.html"  # ต้องตรงกับ aegis_graph.py


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def load_rules():
    if not os.path.exists(RULES_FILE):
        data = {"nids_rules": []}
        save_rules(data)
        return data
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Ensure 'nids_rules' key exists
            if "nids_rules" not in data:
                data["nids_rules"] = []
            return data
    except (json.JSONDecodeError, OSError) as e:
        print(f"[!] Failed to load rules: {e}")
        return {"nids_rules": []}


def save_rules(data):
    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def manage_rules_ui():
    while True:
        clear_screen()
        rules = load_rules()
        print("=======================================================================")
        print("                 AEGIS NIDS - RULE MANAGEMENT UI                       ")
        print("=======================================================================")
        print(f"{'ID':<8} | {'Layer':<14} | {'Attack Name':<32} | {'Policy'}")
        print("-" * 80)

        for r in rules.get("nids_rules", []):
            # ข้าม _comment entries
            if '_comment' in r:
                continue
            policy = r.get('action', 'Alert')
            layer = r.get('layer', '?')
            if policy.upper() in ("BLOCK", "DROP"):
                policy_display = f"\033[91;1m{policy}\033[0m"  # แดง
            else:
                policy_display = f"\033[93;1m{policy}\033[0m"  # เหลือง
            print(f"{r.get('rule_id', 'N/A'):<8} | {layer:<14} | {r.get('name', 'N/A'):<32} | {policy_display}")

        print("\n[Options]")
        print("  [T]oggle Action  : เปลี่ยนสถานะการป้องกัน")
        print("  [A]dd Rule       : เพิ่มกฎการตรวจจับใหม่")
        print("  [D]elete Rule    : ลบกฎที่มีอยู่ออก")
        print("  [B]ack           : กลับสู่เมนูหลัก")

        choice = input("\nSelect action (T/A/D/B): ").strip().upper()

        if choice == 'T':
            target_id = input("Enter Rule ID: ").strip().upper()
            found = False
            for r in rules.get("nids_rules", []):
                if r.get("rule_id", "").upper() == target_id:
                    current = r.get("action", "Alert")
                    # สลับ: Alert <-> Block, Drop <-> Alert
                    if current.upper() in ("BLOCK", "DROP"):
                        r["action"] = "Alert"
                    else:
                        r["action"] = "Block"
                    save_rules(rules)
                    print(f"\n[+] กฎ {target_id} เปลี่ยนเป็น '{r['action']}' เรียบร้อยแล้ว!")
                    found = True
                    break
            if not found:
                print(f"\n[-] ไม่พบ Rule ID '{target_id}' ในระบบ")
            time.sleep(1.5)

        elif choice == 'A':
            print("\n--- Add New Rule ---")
            new_id = input("Rule ID (e.g., R0200): ").strip().upper()
            new_name = input("Attack Name: ").strip()
            new_regex = input("Regex Pattern (e.g., SELECT.*FROM): ").strip()
            new_layer = input("Layer (NETWORK/KERNEL_FILE/KERNEL_PROCESS/PIPE_MONITOR) [NETWORK]: ").strip().upper() or "NETWORK"
            action_input = input("Action (1=Alert, 2=Block, 3=Drop) [Default=1]: ").strip()

            if action_input == "2":
                new_action = "Block"
            elif action_input == "3":
                new_action = "Drop"
            else:
                new_action = "Alert"

            # Auto-derive fast_pattern จาก regex ถ้าไม่ระบุ
            new_fast_pattern = "CUSTOM"
            if new_regex and len(new_regex) >= 3:
                # ดึง 3 ตัวแรกที่เป็น alphanumeric
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
                "category": "Custom Rule",
                "layer": new_layer,
                "fast_pattern": new_fast_pattern,
                "match_pattern": "",
                "regex_pattern": new_regex,
                "severity": "High",
                "action": new_action
            }
            rules.setdefault("nids_rules", []).append(new_rule)
            save_rules(rules)
            print(f"\n[+] สร้างกฎ {new_id} สำเร็จ! ระบบจะทำการโหลดกฎใหม่โดยอัตโนมัติ")
            time.sleep(1.5)

        elif choice == 'D':
            target_id = input("Enter Rule ID to Delete (e.g., R0001): ").strip().upper()
            rules_list = rules.get("nids_rules", [])
            initial_count = len(rules_list)

            # กรองเอากฎที่ไอดี "ไม่ตรง" กับที่ผู้ใช้พิมพ์เก็บไว้ (นั่นคือการลบตัวที่ตรงออก)
            rules["nids_rules"] = [r for r in rules_list if r.get("rule_id", "").upper() != target_id]

            if len(rules["nids_rules"]) < initial_count:
                save_rules(rules)
                print(f"\n[+] ลบกฎ {target_id} ออกจากระบบเรียบร้อยแล้ว!")
            else:
                print(f"\n[-] ไม่พบ Rule ID '{target_id}' ในระบบ")
            time.sleep(1.5)

        elif choice == 'B':
            break

        else:
            print("\n[-] Invalid choice. Please try again.")
            time.sleep(1)


def main_menu():
    while True:
        clear_screen()
        print("========================================")
        print("      AEGIS NIDS - COMMAND CENTER       ")
        print("========================================")
        print(" 1. [RUN]   Launch NIDS Subsystems")
        print(" 2. [RULES] Manage Detection Rules")
        print(" 3. [LOGS]  Reset Anomalous Logs")
        print(" 4. [GRAPH] Generate & View Threat Map")
        print(" 5. [EXIT]  Shutdown Console")
        print("----------------------------------------")
        choice = input("Select Option (1-5): ").strip()

        if choice == '1':
            print("[!] Booting Zig Core, Brain, and Sensors...")
            # ใช้ subprocess.Popen เพื่อเปิดหน้าต่าง launcher แยก
            subprocess.Popen(
                ["cmd", "/c", "start", "AEGIS Launcher", "run_aegis.bat"],
                shell=True
            )
            input("\nPress Enter to return...")

        elif choice == '2':
            manage_rules_ui()

        elif choice == '3':
            os.makedirs("logs", exist_ok=True)
            open("logs/anomalous.json", "w").close()
            print("[+] Logs cleared successfully.")
            input("\nPress Enter...")

        elif choice == '4':
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
