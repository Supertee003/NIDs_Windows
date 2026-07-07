import os
import json
import subprocess
import webbrowser  # เพิ่มไลบรารีสำหรับเปิดเว็บบราวเซอร์อัตโนมัติ
import aegis_graph # โหลดโมดูลกราฟวิเคราะห์ของคุณเข้ามา
import time # เพิ่ม time ไว้ด้านบนสุดของไฟล์ด้วยถ้ายังไม่มี

# แก้ไขให้ชื่อไฟล์ตรงกับเครื่องยนต์หลัก (ตัว R พิมพ์ใหญ่)
RULES_FILE = "Rules.json"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def load_rules():
    if not os.path.exists(RULES_FILE):
        data = {"nids_rules": []} # ปรับโครงสร้างให้ตรงกับเครื่องยนต์ NIDS
        save_rules(data)
        return data
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_rules(data):
    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def manage_rules_ui():
    while True:
        clear_screen()
        rules = load_rules()
        print("=======================================================================")
        print("                 AEGIS NIDS - RULE MANAGEMENT UI                       ")
        print("=======================================================================")
        print(f"{'ID':<6} | {'Attack Name':<32} | {'Policy'}")
        print("-" * 71)
        
        for r in rules.get("nids_rules", []):
            # จัดสี Policy ให้ดูง่ายขึ้น (สีแดงสำหรับ Drop, สีเหลืองสำหรับ BLOCK)
            policy = r.get('action', 'Drop')
            if policy.upper() == "BLOCK":
                policy_display = f"\033[91;1m{policy}\033[0m" # แดง
            else:
                policy_display = f"\033[93;1m{policy}\033[0m" # เหลือง
                
            print(f"{r.get('rule_id', 'N/A'):<6} | {r.get('name', 'N/A'):<32} | {policy_display}")
            
        print("\n[Options]")
        print("  [T]oggle Action  : เปลี่ยนสถานะการป้องกัน")
        print("  [A]dd Rule       : เพิ่มกฎการตรวจจับใหม่")
        print("  [D]elete Rule    : ลบกฎที่มีอยู่ออก")
        print("  [B]ack           : กลับสู่เมนูหลัก")
        
        choice = input("\nSelect action (T/A/D/B): ").strip().upper()
        
        if choice == 'T':
            target_id = input("Enter Rule ID: ").strip().upper()
            found = False
            for r in rules["nids_rules"]:
                if r.get("rule_id", "").upper() == target_id:
                    # สลับสถานะ
                    current = r.get("action", "Drop")
                    r["action"] = "Block" if current == "Drop" else "Drop"
                    save_rules(rules)
                    # print(f"\n[+] กฎ {target_id} เปลี่ยนเป็น '{r['action']}' เรียบร้อยแล้ว!")
                    # found = True
                    break
            #if not found:
                #print("\n[-] ไม่พบ Rule ID นี้ในระบบ")
            #time.sleep(1.5)
            
        elif choice == 'A':
            print("\n--- Add New Rule ---")
            new_id = input("Rule ID (e.g., R0200): ").strip().upper()
            new_name = input("Attack Name: ").strip()
            new_regex = input("Regex Pattern (e.g., SELECT.*FROM): ").strip()
            action_input = input("Action (1=BLOCK, 2=Drop) [Default=1]: ").strip()
            
            new_action = "Drop" if action_input == "2" else "BLOCK"
            
            new_rule = {
                "rule_id": new_id,
                "name": new_name,
                "category": "Custom Rule",
                "layer": "L7_CUSTOM",
                "fast_pattern": "CUSTOM",
                "match_pattern": "",
                "regex_pattern": new_regex,
                "severity": "High",
                "action": new_action
            }
            rules["nids_rules"].append(new_rule)
            save_rules(rules)
            print(f"\n[+] สร้างกฎ {new_id} สำเร็จ! ระบบจะทำการโหลดกฎใหม่โดยอัตโนมัติ")
            time.sleep(1.5)
            
        elif choice == 'D':
            target_id = input("Enter Rule ID to Delete (e.g., R0001): ").strip().upper()
            initial_count = len(rules["nids_rules"])
            
            # กรองเอากฎที่ไอดี "ไม่ตรง" กับที่ผู้ใช้พิมพ์เก็บไว้ (นั่นคือการลบตัวที่ตรงออก)
            rules["nids_rules"] = [r for r in rules["nids_rules"] if r.get("rule_id", "").upper() != target_id]
            
            if len(rules["nids_rules"]) < initial_count:
                save_rules(rules)
                print(f"\n[+] ลบกฎ {target_id} ออกจากระบบเรียบร้อยแล้ว!")
            else:
                print("\n[-] ไม่พบ Rule ID นี้ในระบบ")
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
        choice = input("Select Option (1-5): ")

        if choice == '1':
            print("[!] Booting Zig Core, Brain, and Sensors...")
            subprocess.Popen(["start", "cmd", "/c", "run_aegis.bat"], shell=True)
            
        elif choice == '2':
            manage_rules_ui()
            
        elif choice == '3':
            if os.path.exists("logs/anomalous.json"):
                open("logs/anomalous.json", "w").close()
                print("[+] Logs cleared successfully.")
            input("\nPress Enter...")
            
        elif choice == '4':
            print("\n[!] Generating Advanced Threat Analysis Graph...")
            try:
                # เรียกฟังก์ชันจากไฟล์ aegis_graph.py
                aegis_graph.generate_threat_graph()
                
                # หา path ของไฟล์ HTML ที่ถูกสร้าง
                html_path = os.path.abspath("aegis_threat_map.html")
                
                if os.path.exists(html_path):
                    print(f"[+] Graph generated successfully!")
                    # เปิดเบราว์เซอร์อัตโนมัติ
                    webbrowser.open(f"file://{html_path}")
                else:
                    print("[-] Failed to find the generated map file.")
            except Exception as e:
                print(f"[ERROR] Could not generate graph: {e}")
                print("Make sure you installed required libraries: pip install networkx pyvis")
                
            input("\nPress Enter to return...")
            
        elif choice == '5':
            print("[!] Shutting down console...")
            break

if __name__ == "__main__":
    main_menu()