import json, os, time
from datetime import datetime

LOG_FILE = "logs/anomalous.json"
RULES_FILE = "Rules.json"

# --- [ COLOR PALETTE ] ---
class C:
    RED = '\033[91;1m'
    GREEN = '\033[92;1m'
    YELLOW = '\033[93;1m'
    CYAN = '\033[96;1m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def load_rules():
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"nids_rules": []}

def main():
    while True:
        rules = load_rules()
        attack_summary = {sig['name']: 0 for sig in rules.get('nids_rules', [])}
        stats = {"Total_Alerts": 0, "Total_Dropped": 0}

        lines_to_show = []

        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    stats["Total_Alerts"] = len(lines)
                    
                    for line in lines:
                        if not line.strip(): continue
                        data = json.loads(line)
                        attack_type = data.get("attack_type")
                        if attack_type in attack_summary:
                            attack_summary[attack_type] += 1
                            
                        # สมมติว่าถ้า policy เป็น DROP หรือ BLOCK ให้บวก Total_Dropped
                        if data.get("policy", "").upper() in ["DROP", "BLOCK"]:
                            stats["Total_Dropped"] += 1

                    lines_to_show = lines[-12:] # โชว์ 12 บรรทัดล่าสุด
            except Exception:
                pass

        # --- [ CLEAR SCREEN & HEADER ] ---
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{C.CYAN}╔{'═'*78}╗{C.RESET}")
        header_text = f"🛡️  AEGIS NIDS COMMAND CENTER | TIME: {datetime.now().strftime('%H:%M:%S')}"
        print(f"{C.CYAN}║{C.RESET} {header_text.ljust(76)} {C.CYAN}║{C.RESET}")
        print(f"{C.CYAN}╚{'═'*78}╝{C.RESET}")

        # --- [ NETWORK STATS ] ---
        print(f"\n{C.BOLD}[ OVERALL STATISTICS ]{C.RESET}")
        print(f"  Alerts Triggered: {C.YELLOW}{stats['Total_Alerts']}{C.RESET}   |   Packets Dropped: {C.RED}{stats['Total_Dropped']}{C.RESET}")
        
        # --- [ THREAT COUNTERS ] ---
        print(f"\n{C.BOLD}[ ACTIVE THREAT COUNTERS ]{C.RESET}")
        active_threats = [f"{name}: {C.RED}{count}{C.RESET}" for name, count in attack_summary.items() if count > 0]
        if active_threats:
            # จัดให้อยู่ในบรรทัดละ 3 รายการ
            for i in range(0, len(active_threats), 3):
                print("  " + " | ".join(active_threats[i:i+3]))
        else:
            print(f"  {C.GREEN}✓ No threats matched with rules yet.{C.RESET}")
        
        # --- [ LATEST LOGS TABLE ] ---
        print(f"\n{C.CYAN}┌{'─'*78}┐{C.RESET}")
        print(f"{C.CYAN}│{C.RESET} {C.BOLD}{'TIME':<10} │ {'SOURCE':<23} │ {'THREAT TYPE':<25} │ {'ACTION':<10}{C.RESET} {C.CYAN}│{C.RESET}")
        print(f"{C.CYAN}├{'─'*78}┤{C.RESET}")

        if not lines_to_show:
            print(f"{C.CYAN}│{C.RESET} {'Waiting for traffic...'.center(76)} {C.CYAN}│{C.RESET}")
        
        for line in reversed(lines_to_show): # แสดงจากใหม่สุดไปเก่าสุด
            if not line.strip(): continue
            try:
                data = json.loads(line)
                
                # จัดรูปแบบข้อมูล
                ts_raw = data.get("timestamp", time.time())
                ts = datetime.fromtimestamp(ts_raw).strftime("%H:%M:%S") if isinstance(ts_raw, (int, float)) else ts_raw
                source = str(data.get("source", "Unknown"))[:23]
                attack = str(data.get("attack_type", "Unknown"))[:25]
                policy = str(data.get("policy", "ALERT"))[:10].upper()

                # กำหนดสีตาม Action
                action_color = C.RED if policy in ["DROP", "BLOCK"] else C.YELLOW

                print(f"{C.CYAN}│{C.RESET} {ts:<10} │ {source:<23} │ {attack:<25} │ {action_color}{policy:<10}{C.RESET} {C.CYAN}│{C.RESET}")
            except:
                continue
                
        print(f"{C.CYAN}└{'─'*78}┘{C.RESET}")

        time.sleep(1) # อัปเดตทุก 1 วินาที

if __name__ == "__main__":
    main()