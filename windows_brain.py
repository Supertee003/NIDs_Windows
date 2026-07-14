"""
AEGIS NIDS — Brain (Tier-2/3 Deep Inspection Engine)
====================================================
แก้ไขจากเดิม:
  1. เพิ่มฟังก์ชัน `run_regex_scan()` ที่ขาดหายไป
  2. เพิ่มฟังก์ชัน `apply_firewall_policy()` ที่ขาดหายไป
  3. แก้ตัวแปร `rules_data` → ใช้ `rules` ที่โหลดจาก `load_rules()`
  4. Un-comment `os.system()` สำหรับ firewall block (IPS) — รันด้วยสิทธิ์ Admin เท่านั้น
  5. ทำให้ load rules 1 ครั้ง ใช้ได้ทั้ง main loop และ helper functions
  6. ลด code ซ้ำซ้อน/ลบฟังก์ชันที่ไม่ถูกเรียกใช้
"""
import json
import os
import re
import socket
import subprocess
from datetime import datetime

LOG_FILE = "logs/anomalous.json"
RULES_FILE = "Rules.json"
MAX_PAYLOAD_SIZE = 4096
UDP_IP = "127.0.0.1"
UDP_PORT = 9999


class UI:
    DANGER = '\033[91;1m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RESET = '\033[0m'


# ====================================================================
# GLOBAL STATE (loaded once at startup, reloaded on Rules.json change)
# ====================================================================
_rules_cache = {"nids_rules": []}
_tier2_engine_cache = {}
_last_rule_mod_time = 0.0


def load_rules():
    """โหลด rules จาก Rules.json — return dict"""
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"{UI.YELLOW}[!] Failed to load rules: {e}{UI.RESET}")
    return {"nids_rules": []}


def compile_tier2_rules(rules_data):
    """คอมไพล์ Regex ทั้งหมดเตรียมไว้ใน Memory เพื่อความเร็วขั้นสุด"""
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
                    escaped = re.escape(match_str)
                    escaped = escaped.replace(r"\\x", r"\x")
                    compiled[r["name"]] = re.compile(escaped, re.DOTALL)
                except Exception as e:
                    print(f"[!] Error compiling match_pattern for {r.get('name')}: {e}")
    return compiled


def refresh_rules_if_changed():
    """รีโหลด rules + tier2 engine เมื่อไฟล์ Rules.json ถูก modify"""
    global _rules_cache, _tier2_engine_cache, _last_rule_mod_time
    try:
        current_mtime = os.path.getmtime(RULES_FILE)
    except OSError:
        return

    if current_mtime > _last_rule_mod_time:
        new_rules = load_rules()
        new_engine = compile_tier2_rules(new_rules)
        _rules_cache = new_rules
        _tier2_engine_cache = new_engine
        _last_rule_mod_time = current_mtime
        print(f"{UI.YELLOW}[!] Rules reloaded: {len(new_rules.get('nids_rules', []))} rules, "
              f"{len(new_engine)} compiled regexes.{UI.RESET}")


# ====================================================================
# FIREWALL / IPS HELPERS
# ====================================================================
def apply_firewall_block(ip_address, rule_name="Aegis-NIDS"):
    """สั่ง Windows Firewall ให้ Block IP ของแฮกเกอร์ (ต้องรันด้วยสิทธิ์ Admin)"""
    if not ip_address or ip_address == "Unknown":
        return False

    fw_rule_name = f"AEGIS_BLOCK_{ip_address}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={fw_rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip_address}",
        f"description=Blocked by Aegis NIDS rule: {rule_name}",
    ]
    try:
        subprocess.run(cmd, capture_output=True, check=True)
        print(f"{UI.DANGER}[CORE] IP {ip_address} BLOCKED by rule: {rule_name}{UI.RESET}")
        return True
    except subprocess.CalledProcessError as e:
        # มี rule อยู่แล้ว → ไม่ถือว่า error
        if "already exists" in (e.stderr.decode(errors='ignore') if e.stderr else "").lower():
            return True
        print(f"{UI.YELLOW}[!] Firewall block failed for {ip_address}: {e}{UI.RESET}")
        return False
    except Exception as e:
        print(f"{UI.YELLOW}[!] Firewall error: {e}{UI.RESET}")
        return False


def apply_firewall_policy(data):
    """Apply firewall policy ตามที่ Zig/Brain สั่ง — ใช้ src_ip จาก payload"""
    src_ip = data.get("src_ip") or data.get("source") or "Unknown"
    rule_name = data.get("attack_type", "Unknown")
    policy = (data.get("policy") or "ALERT").upper()

    if policy in ("BLOCK", "DROP"):
        return apply_firewall_block(src_ip, rule_name)
    # Alert / others — ไม่ block
    return False


# ====================================================================
# TIER-2 SCANNER (ใช้ regex engine ที่ compile ไว้)
# ====================================================================
def run_regex_scan(payload):
    """
    สแกน payload ด้วย regex engine — return (rule_name, rule_dict) ถ้า match, else (None, None)
    """
    if not payload:
        return None, None

    safe_payload = str(payload)[:MAX_PAYLOAD_SIZE]

    for rule in _rules_cache.get("nids_rules", []):
        regex_matcher = _tier2_engine_cache.get(rule.get("name"))
        if regex_matcher and regex_matcher.search(safe_payload):
            return rule.get("name"), rule

    return None, None


# ====================================================================
# LOG WRITER
# ====================================================================
def write_anomaly_log(entry):
    """เขียน entry ลง log file เป็น JSONL (1 record per line)"""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    except Exception as e:
        print(f"{UI.YELLOW}[!] Log write failed: {e}{UI.RESET}")


# ====================================================================
# MAIN BRAIN LOOP
# ====================================================================
def main():
    os.makedirs("logs", exist_ok=True)

    print(f"{UI.CYAN}--- AEGIS BRAIN: TIER-2 DEEP INSPECTION ENGINE ACTIVE ---{UI.RESET}")

    # Initial rules load
    refresh_rules_if_changed()
    print(f"[*] Loaded {len(_rules_cache.get('nids_rules', []))} rules, "
          f"{len(_tier2_engine_cache)} compiled regexes.")

    # Bind UDP socket ด้วย SO_REUSEADDR เพื่อกัน port ค้าง
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((UDP_IP, UDP_PORT))
    print(f"[*] Listening for Tier-1 alerts on UDP {UDP_IP}:{UDP_PORT}...")

    while True:
        # ตรวจ Rules.json ทุกรอบ — ถ้าเปลี่ยนให้ reload
        refresh_rules_if_changed()

        try:
            msg_bytes, addr = sock.recvfrom(65535)
            raw_payload = msg_bytes.decode("utf-8", errors="ignore").strip()
            print(f"\n[DEBUG] Packet from ZIG ({len(raw_payload)}B): {raw_payload[:200]}...")

            log_entry = json.loads(raw_payload)
            source = log_entry.get("source", "UNKNOWN")
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # === Case 1: Tier-1 พบ match แล้ว (Zig ส่งมาแจ้ง) ===
            if log_entry.get("reason", "").startswith("Tier-1"):
                rule_name = log_entry.get("attack_type", "Unknown")
                policy = (log_entry.get("policy") or "ALERT").upper()
                print(f"{UI.YELLOW}[TIER-1 ALERT]{UI.RESET} {ts} | {rule_name} | policy={policy} | src={source}")

                # Apply IPS ถ้า policy = BLOCK/DROP
                if policy in ("BLOCK", "DROP"):
                    apply_firewall_policy(log_entry)

                write_anomaly_log(log_entry)
                continue

            # === Case 2: Forwarded (no Tier-1 match) → สแกน Tier-2/3 ===
            inner_data = log_entry.get("raw_payload", raw_payload)
            match_name, matched_rule = run_regex_scan(inner_data)

            if match_name:
                policy = (matched_rule.get("action") or "ALERT").upper()
                print(f"{UI.CYAN}[PYTHON MATCH]{UI.RESET} {ts} | {match_name} | "
                      f"policy={policy} | layer={matched_rule.get('layer', '?')}")

                # Update log entry ก่อนเขียน
                log_entry["attack_type"] = match_name
                log_entry["policy"] = policy
                log_entry["rule_id"] = matched_rule.get("rule_id", "UNKNOWN")
                log_entry["reason"] = "Tier-3 Regex Confirmed Match"
                log_entry["layer"] = matched_rule.get("layer", "")

                # Apply IPS
                if policy in ("BLOCK", "DROP"):
                    apply_firewall_policy(log_entry)

                write_anomaly_log(log_entry)
            else:
                print(f"[INFO] {ts} | Packet inspected. No Tier-2 match.")

        except json.JSONDecodeError as e:
            print(f"{UI.YELLOW}[!] JSON Decode Error: {e}{UI.RESET}")
        except KeyboardInterrupt:
            print(f"\n{UI.YELLOW}[!] Shutting down brain...{UI.RESET}")
            break
        except Exception as e:
            print(f"{UI.DANGER}[ERROR]{UI.RESET} {e}")


if __name__ == "__main__":
    main()
