import json, os, socket, re
import subprocess
from datetime import datetime

LOG_FILE = "logs/anomalous.json"
RULES_FILE = "Rules.json"
MAX_PAYLOAD_SIZE = 4096

class UI:
    DANGER = '\033[91;1m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'

def load_rules():
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"nids_rules": []}

def apply_firewall_block(ip_address):
    """ สั่ง Windows Firewall ให้ Block IP ของแฮกเกอร์ """
    rule_name = f"AEGIS_AUTO_BLOCK_{ip_address}"
    try:
        # ใช้ netsh add rule เพื่อบล็อก IP
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}"
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except Exception as e:
        print(f"[!] Firewall Error: {e}")
        return False

def process_threat(data, action):
    src_ip = data.get("src_ip", "Unknown")
    
    if action == "BLOCK":
        if apply_firewall_block(src_ip):
            print(f"[-] IPS ACTIVE: IP {src_ip} has been blocked.")
    elif action == "ALERT":
        print(f"[!] NIDS ALERT: Potential threat from {src_ip}")

def process_brain_logic():
    while True:
        
            msg_bytes, addr = server_sock.recvfrom(65535) # รับข้อมูลขนาดใหญ่
            data = json.loads(msg_bytes.decode('utf-8', errors='ignore'))
            
            # กรณีที่ 1: Zig ตรวจไม่พบ (Forwarded) -> ต้องรัน Regex
            if data.get("reason") == "Forwarded: No Tier-1 Match":
                payload = data.get("raw_payload", "")
                match_rule = None
                
                # รัน 66 Regex Rules (Tier-2)
                for name, pattern in compiled_regex.items():
                    if pattern.search(payload):
                        match_rule = name
                        break
                
                if match_rule:
                    # สั่งการตาม Policy (Block/Drop) ผ่าน Windows Firewall
                    print(f"{UI.DANGER}[PYTHON MATCH] {datetime.now()} | Threat: {match_rule}{UI.RESET}")
                    apply_firewall_policy(data) 
                    write_anomaly_log(data, match_rule) # เขียนลง Log เพื่อให้ 3 การแสดงผลทำงาน
            
            # กรณีที่ 2: Zig ตรวจพบแล้ว (Fast Pattern Match)
            else:
                # ถ้า Zig ส่งมาว่าเป็น Drop เราต้องมาจัดการ Firewall ที่นี่
                if data.get("policy") == "Drop":
                    apply_firewall_policy(data)
                write_anomaly_log(data, data.get("attack_type"))

def compile_tier2_rules(rules_data):
    """ คอมไพล์ Regex ทั้งหมดเตรียมไว้ใน Memory เพื่อความเร็วขั้นสุด """
    compiled = {}
    for r in rules_data.get("nids_rules", []):
        regex_str = r.get("regex_pattern", "")
        
        if regex_str:
            try:
                compiled[r["name"]] = re.compile(regex_str, re.DOTALL)
            except Exception as e:
                print(f"[!] Invalid regex in {r.get('name')}: {e}")
                
        else:
            match_str = r.get("match_pattern", "")
            if match_str:
                try:
                    escaped_match_str = re.escape(match_str)
                    escaped_match_str = escaped_match_str.replace(r"\\x", r"\x")
                    compiled[r["name"]] = re.compile(escaped_match_str, re.DOTALL)
                except Exception as e:
                    print(f"[!] Error compiling match_pattern for {r.get('name')}: {e}")

    return compiled

def execute_block(ip_address, rule_name):
    """ สั่ง Block IP ผ่าน Windows Firewall และแจ้งเตือน Console """
    try:
        # 1. สร้างชื่อกฎให้เป็นระบบเพื่อให้ลบออกง่าย (เช่น AEGIS_BLOCK_192.168.1.5)
        fw_rule_name = f"AEGIS_BLOCK_{ip_address}"
        
        # 2. ใช้ netsh สั่ง Block ทันที
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={fw_rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}",
            "description=Blocked by Aegis NIDS Tier-2"
        ]
        
        # รันคำสั่ง (ต้องรัน Python ด้วยสิทธิ์ Admin)
        subprocess.run(cmd, capture_output=True, check=True)
        
        print(f"{UI.DANGER}[CORE] IP {ip_address} has been PERMANENTLY BLOCKED by Rule: {rule_name}{UI.RESET}")
        return True
    except Exception as e:
        print(f"{UI.YELLOW}[!] Failed to block IP {ip_address}: {e}{UI.RESET}")
        return False

def main():
    # 1. สร้างโฟลเดอร์ logs อัตโนมัติ ป้องกัน Error เขียนไฟล์ไม่เจอ
    os.makedirs("logs", exist_ok=True)

    print(f"{UI.CYAN}--- AEGIS BRAIN: TIER-2 DEEP INSPECTION ENGINE ACTIVE ---{UI.RESET}")
    
    rules = load_rules()
    tier2_engine = compile_tier2_rules(rules)
    print(f"[*] Compiled {len(tier2_engine)} Regex rules for Deep Inspection.")

    UDP_IP = "127.0.0.1"
    UDP_PORT = 9999
    
    # 2. แก้ปัญหา Port 9999 ค้าง (WinError 10048) ปิดเปิดใหม่ได้ทันที
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((UDP_IP, UDP_PORT))
    
    print(f"[*] Listening for Tier-1 Suspects on UDP {UDP_IP}:{UDP_PORT}...")

    # รีโหลด Rules อัตโนมัติ
    last_rule_mod_time = os.path.getmtime(RULES_FILE)

    while True:

        current_rule_mod_time = os.path.getmtime(RULES_FILE)
        if current_rule_mod_time > last_rule_mod_time:
            print(f"{UI.YELLOW}[!] System Admin changed Policy. Reloading Core Brain...{UI.RESET}")
            rules = load_rules()
            tier2_engine = compile_tier2_rules(rules)
            last_rule_mod_time = current_rule_mod_time

        try:
            msg_bytes, addr = sock.recvfrom(65535)
            raw_payload = msg_bytes.decode("utf-8", errors="ignore").strip()

            print(f"\n[DEBUG] Raw packet from ZIG: {raw_payload[:200]}...")

            # 3. แปลงข้อมูลที่ Zig ส่งมาให้เป็น JSON Object
            log_entry = json.loads(raw_payload)

            data = log_entry

            source = log_entry.get("source", "UNKNOWN")
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # =========================================================
            # 🧠 Case 1: L4 Fast Pattern Match (Tier 1) 
            # ถ้าเป็น L4 แท้ๆ ให้บันทึกลง Log ส่งไปให้ Rust แจ้งเตือนเลย
            # =========================================================
            if source == "L4":
                print(f"{UI.YELLOW}[TIER-1 ALERT]{UI.RESET} {ts} | ZIG Blocked L4 Threat!")
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(json.dumps(log_entry) + "\n")
                continue
            
            # =========================================================
            # 🧠 Case 2: Deep Inspection ด้วย Python Regex (Tier 3)
            # =========================================================
            # 4. สำคัญมาก: ดึงเฉพาะข้อมูลการโจมตีจริงๆ ที่อยู่ในคีย์ "raw_payload" ออกมาสแกน
            inner_data = log_entry.get("raw_payload", raw_payload)
            safe_payload = str(inner_data)[:MAX_PAYLOAD_SIZE]
            
            match_found = False

            # 5. สแกนด้วย Regex (ไม่ต้องเช็ค Layer แล้ว ให้ครอบคลุมทุกการโจมตี)
            for rule in rules.get("nids_rules", []):
                regex_matcher = tier2_engine.get(rule["name"])
                
                if regex_matcher and regex_matcher.search(safe_payload):
                    print(f"{UI.CYAN}[PYTHON MATCH]{UI.RESET} {ts} | Threat: {rule['name']} | Layer: {source}")
                    
                    log_entry["attack_type"] = rule["name"]
                    log_entry["policy"] = rule.get("action", "ALERT")
                    log_entry["rule_id"] = rule.get("rule_id", "UNKNOWN")
                    log_entry["reason"] = "Tier-3 Regex Confirmed Match"
                    
                                
                    policy_action = rule.get("action", "ALERT").upper()
                                
                    # 🚀 เพิ่มส่วนนี้: ถ้าแอดมินตั้งค่าเป็น DROP ให้สั่ง Firewall บล็อกทันที
                    if policy_action == "DROP":
                        print(f"{UI.DANGER}[IPS ACTIVATED] Blocking attack at Windows Firewall!{UI.RESET}")
                        # สมมติว่ามีตัวแปร source_ip ของแฮกเกอร์ (ถ้าไม่มี ให้ละไว้หรือคอมเมนต์ออก)
                        # os.system(f'netsh advfirewall firewall add rule name="AEGIS Block {source_ip}" dir=in action=block remoteip={source_ip}')

                    log_entry["attack_type"] = rule["name"]
                    log_entry["policy"] = policy_action
                    log_entry["rule_id"] = rule.get("rule_id", "UNKNOWN")
                    # ... เซฟลงไฟล์ต่อ ...

                    # 6. เขียนลงไฟล์ Anomalous.json ส่งต่อให้ Rust ทันที!
                    with open(LOG_FILE, "a", encoding="utf-8") as f:
                        f.write(json.dumps(log_entry) + "\n")
                    
                    match_found = True
                    break # เจอข้อแรกแล้วหยุด
            
            if not match_found:
                print(f"[INFO] Packet inspected. No Tier-2 match found.")
            
            if data.get("reason") == "Forwarded: No Tier-1 Match":
                # รัน 66 Regex Rules ที่นี่
                result = run_regex_scan(data["raw_payload"])
                if result:
                    # ดึงข้อมูลจาก Data ที่ Zig ส่งมา
                    src_ip = data.get("src_ip", "Unknown")
                    rule_name = result # ชื่อกฎที่ Match
                    
                    # ค้นหา Policy จาก Rules.json (สมมติว่าคุณโหลด rules ไว้ในตัวแปร rules_data)
                    policy = "ALERT" # ค่าเริ่มต้น
                    for r in rules_data.get("nids_rules", []):
                        if r["name"] == rule_name:
                            policy = r.get("action", "ALERT").upper()
                            break

                    print(f"{UI.DANGER}[!] Tier-2 Match: {rule_name} | Policy: {policy}{UI.RESET}")

                    # --- ลอจิกการทำงานตาม Policy ---
                    if policy == "BLOCK" and src_ip != "Unknown":
                        if execute_block(src_ip, rule_name):
                            status_action = "BLOCKED"
                        else:
                            status_action = "BLOCK_FAILED"
                    else:
                        status_action = "DETECTED"

                    # 3. บันทึกลง Logs เพื่อให้ Console อ่าน
                    log_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "source": src_ip,
                        "attack_type": rule_name,
                        "policy": policy,
                        "status": status_action, # บอก Console ว่า Block สำเร็จไหม
                        "payload_snippet": data["raw_payload"][:50]
                    }
                    
                    with open(LOG_FILE, "a", encoding="utf-8") as f:
                        f.write(json.dumps(log_entry) + "\n")

        except json.JSONDecodeError as e:
            print(f"{UI.YELLOW}[!] JSON Decode Error: {e}{UI.RESET}")
        except Exception as e:
            print(f"{UI.DANGER}[ERROR]{UI.RESET} {e}")

if __name__ == "__main__":
    main()