"""
AEGIS BRAIN — Tier-2 Deep Inspection Engine (Python)
====================================================
UDP listener on 127.0.0.1:9999 receives suspicious packets from Zig Core.
Runs regex-based deep inspection against compiled rule patterns.
Enforces IPS policy via Windows Firewall (netsh advfirewall) + C++ Bridge.

3-Layer Architecture:
  - NETWORK layer: TCP/WFP captured packets (source: L7, L4, L3)
  - KERNEL_FILE layer: Minifilter filesystem events (source: L7_PIPE, KERNEL_FILE)
  - KERNEL_PROCESS layer: Process create/exit events (source: KERNEL_PROCESS)
  - PIPE_MONITOR layer: Named Pipe events (source: L2_PIPE)

Bridge Integration (Phase 1):
  - Import aegis_bridge_ctypes for C++ IPC Bridge
  - Push Tier-2 match results to Bridge (for Dashboard)
  - Use Bridge DEFCON level for IPS policy decisions
  - Pop events from Bridge queue for cross-subsystem communication
"""

import json, os, socket, re, sys, time
import struct
import subprocess
from datetime import datetime

# ====== MessagePack + Length-Prefix Framing (Fix #2) ======
# Format: [4 bytes: payload length (big-endian)] + [MsgPack payload]
# Fallback to JSON if MsgPack unavailable (graceful degradation)
try:
    import msgpack
    MSGPACK_AVAILABLE = True
except ImportError:
    MSGPACK_AVAILABLE = False
    print("[AEGIS BRAIN] Warning: msgpack not installed — pip install msgpack")
    print("[AEGIS BRAIN] Falling back to JSON (less efficient)")

MAX_UDP_PAYLOAD = 65535  # UDP max payload size

# ====== Sanity Check + Circuit Breaker + Sequence Tracking (Enhancement) ======
class UdpCircuitBreaker:
    """Circuit Breaker สำหรับ Zig→Brain UDP channel.
    ถ้า decode ล้มติดต่อกันเกิน threshold → เปิด circuit (หยุดรับชั่วคราว)
    """
    def __init__(self, fail_threshold=10, open_duration=5.0):
        self.fail_threshold = fail_threshold
        self.open_duration = open_duration
        self.fail_count = 0
        self.state = "closed"  # closed / open / half-open
        self.open_until = 0.0

    def allow(self):
        import time
        if self.state == "open":
            if time.monotonic() >= self.open_until:
                self.state = "half-open"
                return True
            return False
        return True

    def record_success(self):
        if self.state == "half-open":
            self.state = "closed"
        self.fail_count = 0

    def record_failure(self):
        self.fail_count += 1
        if self.fail_count >= self.fail_threshold:
            import time
            self.state = "open"
            self.open_until = time.monotonic() + self.open_duration
            print(f"[CB] Brain Circuit Breaker OPEN — {self.fail_count} decode failures, backing off {self.open_duration}s")

brain_circuit_breaker = UdpCircuitBreaker()

# Sequence number tracking for UDP reordering detection
_last_sequence: int = 0
_reorder_count: int = 0
_gap_count: int = 0

def sanity_check_decoded(data: dict) -> bool:
    """Sanity check ข้อมูลหลัง decode — ป้องกัน corrupted data จาก UDP errors.
    ตรวจ: required fields, type validity, range validity, not empty.
    """
    if not isinstance(data, dict):
        return False
    # Required fields from Zig alert
    required = ["attack_type", "policy", "source"]
    for field in required:
        if field not in data:
            return False
        val = data[field]
        if not isinstance(val, (str, int, float)):
            return False
    # IP should be uint32 (0 to 4294967295) or string
    for ip_field in ["source_ip", "dest_ip"]:
        if ip_field in data:
            ip = data[ip_field]
            if isinstance(ip, int) and (ip < 0 or ip > 0xFFFFFFFF):
                return False
    # Port should be 0-65535
    for port_field in ["source_port", "dest_port"]:
        if port_field in data:
            port = data[port_field]
            if isinstance(port, int) and (port < 0 or port > 65535):
                return False
    # Protocol should be 0-255
    if "protocol" in data:
        proto = data["protocol"]
        if isinstance(proto, int) and (proto < 0 or proto > 255):
            return False
    return True

def track_sequence(data: dict):
    """Track sequence numbers to detect UDP reordering/gaps.
    Zig can optionally include 'seq' field in MsgPack payloads.
    """
    global _last_sequence, _reorder_count, _gap_count
    seq = data.get("seq")
    if seq is None:
        return  # No sequence tracking
    if isinstance(seq, int) and seq > 0:
        if seq < _last_sequence:
            _reorder_count += 1
            if _reorder_count % 100 == 1:
                print(f"[UDP] Reordering detected: seq={seq} < last={_last_sequence} (total reorder: {_reorder_count})")
        elif seq > _last_sequence + 1:
            gap = seq - _last_sequence - 1
            _gap_count += gap
            if _gap_count > 100 and _gap_count % 100 == 0:
                print(f"[UDP] Packet loss: gap of {gap} after seq={_last_sequence} (total gaps: {_gap_count})")
        _last_sequence = max(_last_sequence, seq)


def recv_length_prefixed(sock, timeout=1.0):
    """
    Read a length-prefixed message from UDP socket.
    Format: [4B length BE] + [MsgPack payload]
    Returns decoded dict or None on error.
    """
    sock.settimeout(timeout)
    try:
        msg_bytes, addr = sock.recvfrom(MAX_UDP_PAYLOAD)
    except socket.timeout:
        return None, None

    if len(msg_bytes) < 4:
        # Too short for length prefix — try JSON fallback
        try:
            raw = msg_bytes.decode("utf-8", errors="ignore").strip()
            return json.loads(raw), addr
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, addr

    # Read 4-byte length prefix (big-endian)
    payload_len = struct.unpack(">I", msg_bytes[:4])[0]
    payload = msg_bytes[4:]

    # Verify payload length matches
    if payload_len > 0 and len(payload) >= payload_len:
        payload = payload[:payload_len]

    # Try MsgPack decode first
    if MSGPACK_AVAILABLE:
        try:
            decoded = msgpack.unpackb(payload, raw=False)
            if isinstance(decoded, dict):
                return decoded, addr
        except Exception:
            pass

    # Fallback: try JSON
    try:
        raw = payload.decode("utf-8", errors="ignore").strip()
        return json.loads(raw), addr
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Last resort: try the entire message as JSON (legacy compatibility)
        try:
            raw = msg_bytes.decode("utf-8", errors="ignore").strip()
            return json.loads(raw), addr
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, addr

# 🔗 C++ IPC Bridge — เชื่อม Brain ↔ Bridge ↔ Dashboard
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "bridge"))
try:
    import aegis_bridge_ctypes as bridge
    BRIDGE_AVAILABLE = True
except ImportError:
    print("[AEGIS BRAIN] Warning: aegis_bridge_ctypes not found — running without Bridge")
    BRIDGE_AVAILABLE = False

LOG_FILE = "logs/anomalous.json"
RULES_FILE = "Rules.json"
MAX_PAYLOAD_SIZE = 4096

class UI:
    DANGER = '\033[91;1m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RESET = '\033[0m'

# ====== Rule Loading ======

def load_rules():
    """Load Rules.json, skip _comment entries."""
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        # Filter out _comment pseudo-rules
        rules = [r for r in raw.get("nids_rules", [])
                 if isinstance(r, dict) and "rule_id" in r]
        return {"nids_rules": rules}
    return {"nids_rules": []}

# ====== Firewall IPS ======

def apply_firewall_block(ip_address, rule_name="AEGIS"):
    """Block attacker IP via Windows Firewall (netsh advfirewall)."""
    fw_rule_name = f"AEGIS_BLOCK_{ip_address}"
    try:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={fw_rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}",
            f"description=Blocked by Aegis NIDS Tier-2 Rule {rule_name}"
        ]
        subprocess.run(cmd, capture_output=True, check=True)
        print(f"{UI.DANGER}[IPS] IP {ip_address} has been BLOCKED by Rule: {rule_name}{UI.RESET}")

        # 🔗 Push block to C++ Bridge (for Dashboard DEFCON update)
        if BRIDGE_AVAILABLE:
            bridge.block_ip(ip_address)
            bridge.update_defcon(
                critical=0, blocked=1, kernel=0, total=1
            )

        return True
    except Exception as e:
        print(f"{UI.YELLOW}[!] Failed to block IP {ip_address}: {e}{UI.RESET}")
        return False

# ====== Regex Engine ======

def compile_tier2_rules(rules_data):
    """Compile all regex/match patterns from rules into fast regex objects."""
    compiled = {}
    for r in rules_data.get("nids_rules", []):
        name = r.get("name", "")
        regex_str = r.get("regex_pattern", "")
        match_str = r.get("match_pattern", "")

        # Prefer regex_pattern first (most specific)
        if regex_str:
            try:
                compiled[name] = re.compile(regex_str, re.DOTALL)
            except Exception as e:
                print(f"{UI.YELLOW}[!] Invalid regex in {name}: {e}{UI.RESET}")

        # Fall back to match_pattern (literal string match)
        elif match_str:
            try:
                escaped = re.escape(match_str)
                # Allow hex escapes to remain as literal patterns
                escaped = escaped.replace(r"\\x", r"\x")
                compiled[name] = re.compile(escaped, re.DOTALL)
            except Exception as e:
                print(f"{UI.YELLOW}[!] Error compiling match_pattern for {name}: {e}{UI.RESET}")

    return compiled

def run_regex_scan(payload, tier2_engine, rules_data):
    """
    Scan a payload against all compiled Tier-2 regex rules.
    Returns (rule_name, policy, rule_id, severity) if match found, else None.
    """
    safe_payload = str(payload)[:MAX_PAYLOAD_SIZE]

    for r in rules_data.get("nids_rules", []):
        name = r.get("name", "")
        rule_id = r.get("rule_id", "UNKNOWN")
        regex_matcher = tier2_engine.get(name)

        if regex_matcher and regex_matcher.search(safe_payload):
            policy = r.get("action", "Alert").upper()
            severity_str = r.get("severity", "Medium")
            severity_map = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
            severity = severity_map.get(severity_str, 1)
            return (name, policy, rule_id, severity)

    return None

# ====== Log Writing ======

def write_anomaly_log(log_entry, attack_type, policy, rule_id, status="DETECTED"):
    """Write an anomaly log entry to anomalous.json."""
    log_entry["attack_type"] = attack_type
    log_entry["policy"] = policy
    log_entry["rule_id"] = rule_id
    log_entry["status"] = status
    log_entry["brain_timestamp"] = datetime.now().isoformat()

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")

# ====== Bridge Event Polling ======

def poll_bridge_events():
    """Poll C++ Bridge for events from other subsystems (Zig, Rust, Go)."""
    if not BRIDGE_AVAILABLE:
        return

    count = bridge.get_event_count()
    for _ in range(min(count, 50)):  # Process up to 50 events per poll
        event = bridge.pop_event()
        if event is None:
            break

        # Process Tier-1 events from Zig Core that need Tier-2 inspection
        if event.tier_result == 1:  # Tier-1 match from Zig
            defcon = bridge.get_defcon_level()
            try:
                label = bridge.get_defcon_label() if BRIDGE_AVAILABLE else "UNKNOWN"
            except Exception:
                label = "UNKNOWN"
            print(f"{UI.CYAN}[BRIDGE]{UI.RESET} Tier-1 event received — "
                  f"Rule ID: {event.rule_id} | DEFCON: {defcon} ({label})")

        elif event.tier_result == 0:  # Forwarded — no Tier-1 match
            # These events need Tier-2 regex inspection
            pass  # Already handled via UDP from Zig

# ====== Main Brain Loop ======

def main():
    global BRIDGE_AVAILABLE

    os.makedirs("logs", exist_ok=True)

    print(f"{UI.CYAN}--- AEGIS BRAIN: TIER-2 DEEP INSPECTION ENGINE ACTIVE ---{UI.RESET}")

    # 🔗 Initialize C++ IPC Bridge
    if BRIDGE_AVAILABLE:
        rc = bridge.bridge_init()
        if rc == 0:
            print(f"{UI.GREEN}[BRIDGE] C++ IPC Bridge initialized — Python Brain connected{UI.RESET}")
        else:
            print(f"{UI.YELLOW}[BRIDGE] Warning: Bridge init failed (rc={rc}), running in standalone mode{UI.RESET}")
            BRIDGE_AVAILABLE = False
    else:
        print(f"{UI.YELLOW}[BRIDGE] aegis_bridge_ctypes not available — running in standalone mode{UI.RESET}")

    rules_data = load_rules()
    tier2_engine = compile_tier2_rules(rules_data)
    print(f"{UI.GREEN}[*] Compiled {len(tier2_engine)} regex rules for Deep Inspection.{UI.RESET}")

    # Show Bridge DEFCON status
    if BRIDGE_AVAILABLE:
        defcon = bridge.get_defcon_level()
        label = bridge.get_defcon_label()
        print(f"{UI.GREEN}[BRIDGE] Current DEFCON: {defcon} ({label}){UI.RESET}")

    UDP_IP = "127.0.0.1"
    UDP_PORT = 9999

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((UDP_IP, UDP_PORT))

    print(f"{UI.GREEN}[*] Listening for Tier-1 Suspects on UDP {UDP_IP}:{UDP_PORT}...{UI.RESET}")

    # Hot-reload: watch Rules.json mtime for changes
    last_rule_mod_time = os.path.getmtime(RULES_FILE) if os.path.exists(RULES_FILE) else 0

    # Bridge event polling counter
    bridge_poll_counter = 0

    while True:
        # --- Hot-reload check ---
        if os.path.exists(RULES_FILE):
            current_mod_time = os.path.getmtime(RULES_FILE)
            if current_mod_time > last_rule_mod_time:
                print(f"{UI.YELLOW}[!] Policy changed. Reloading Tier-2 Brain...{UI.RESET}")
                rules_data = load_rules()
                tier2_engine = compile_tier2_rules(rules_data)
                last_rule_mod_time = current_mod_time
                print(f"{UI.GREEN}[*] Re-compiled {len(tier2_engine)} regex rules.{UI.RESET}")

        # 🔗 Poll Bridge events every 10 iterations
        bridge_poll_counter += 1
        if bridge_poll_counter >= 10 and BRIDGE_AVAILABLE:
            bridge_poll_counter = 0
            poll_bridge_events()

        try:
            # Read length-prefixed MsgPack message (Fix #2)
            # Format: [4B length BE] + [MsgPack payload]
            # Fallback to JSON if MsgPack unavailable
            # Circuit Breaker: ถ้าเปิด → skip recv ชั่วคราว
            if not brain_circuit_breaker.allow():
                continue

            log_entry, addr = recv_length_prefixed(sock, timeout=1.0)
            if log_entry is None:
                continue  # No valid message — normal timeout or decode error

            # Sanity Check: verify decoded data is valid (Enhancement)
            if not sanity_check_decoded(log_entry):
                brain_circuit_breaker.record_failure()
                print(f"[SANITY] Invalid alert data from {addr} — skipping")
                continue

            brain_circuit_breaker.record_success()

            # Sequence tracking: detect UDP reordering/gaps
            track_sequence(log_entry)

            # Convert MsgPack integer IP to dotted notation (if needed)
            # MsgPack sends source_ip as integer from Zig
            source = log_entry.get("source", "UNKNOWN")
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Extract attacker IP from Zig packet data
            src_ip = log_entry.get("src_ip", log_entry.get("source_ip", "Unknown"))
            # Zig may send "WFP_PIPE" / "TCP_SOCKET" as source — use addr as fallback
            if src_ip in ("WFP_PIPE", "TCP_SOCKET", "UNKNOWN", "Unknown", None):
                src_ip = addr[0] if addr else "Unknown"

            # =========================================================
            # Case 1: Zig already matched (Fast Pattern / Tier-1 Verified)
            #   Zig sends: attack_type, policy, severity, rule_id
            #   Brain only enforces IPS if policy requires blocking
            # =========================================================
            if log_entry.get("attack_type") and log_entry.get("reason") != "Forwarded: No Tier-1 Match":
                attack_type = log_entry.get("attack_type", "Unknown")
                policy = log_entry.get("policy", "Alert").upper()
                rule_id = log_entry.get("rule_id", "UNKNOWN")
                severity = log_entry.get("severity", "High")

                # 🔗 Use Bridge IPS decision for Tier-1 verified alerts
                if BRIDGE_AVAILABLE:
                    severity_map = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
                    sev_int = severity_map.get(severity, 1)
                    ips_decision = bridge.ips_decide(rule_id, sev_int, src_ip, policy.lower())
                    if ips_decision == "block":
                        policy = "BLOCK"

                print(f"{UI.CYAN}[TIER-1 VERIFIED]{UI.RESET} {ts} | {attack_type} | Policy: {policy} | Severity: {severity}")

                # Enforce IPS: block attacker IP if policy is DROP/BLOCK
                status = "DETECTED"
                if policy in ("DROP", "BLOCK") and src_ip != "Unknown":
                    if apply_firewall_block(src_ip, rule_id):
                        status = "BLOCKED"
                    else:
                        status = "BLOCK_FAILED"

                write_anomaly_log(log_entry, attack_type, policy, rule_id, status)
                continue

            # =========================================================
            # Case 2: No Tier-1 Match — Brain must run full regex scan
            #   Zig sends: raw_payload with reason "Forwarded: No Tier-1 Match"
            # =========================================================
            raw_payload_str = str(log_entry)
            payload = log_entry.get("raw_payload", raw_payload_str)

            result = run_regex_scan(payload, tier2_engine, rules_data)
            if result:
                match_name, match_policy, match_rule_id, match_severity = result
                print(f"{UI.DANGER}[TIER-2 MATCH]{UI.RESET} {ts} | Threat: {match_name} | Policy: {match_policy} | Src: {src_ip}")

                # 🔗 Push Tier-2 match to C++ Bridge (for Dashboard)
                if BRIDGE_AVAILABLE:
                    bridge.push_tier2_match(
                        rule_id=match_rule_id,
                        src_ip=src_ip if src_ip != "Unknown" else "0.0.0.0",
                        dst_ip="0.0.0.0",
                        src_port=0,
                        dst_port=0,
                        protocol=6,
                        severity=match_severity,
                    )
                    # Use Bridge IPS decision for Tier-2 matches
                    ips_decision = bridge.ips_decide(
                        match_rule_id, match_severity, src_ip, match_policy.lower()
                    )
                    if ips_decision == "block":
                        match_policy = "BLOCK"

                # Enforce IPS
                status = "DETECTED"
                if match_policy in ("DROP", "BLOCK") and src_ip != "Unknown":
                    if apply_firewall_block(src_ip, match_rule_id):
                        status = "BLOCKED"
                    else:
                        status = "BLOCK_FAILED"

                write_anomaly_log(log_entry, match_name, match_policy, match_rule_id, status)
            else:
                print(f"[INFO] {ts} | Packet from {source} inspected — no Tier-2 match found.")

        except socket.timeout:
            # No UDP data — normal, allows Bridge polling
            continue
        except json.JSONDecodeError as e:
            print(f"{UI.YELLOW}[!] JSON Decode Error from {addr}: {e}{UI.RESET}")
        except Exception as e:
            # Graceful degradation: ไม่ crash ถ้าเกิดข้อผิดพลาด
            # ระบบยังรอรับ UDP packet ต่อไป
            print(f"{UI.DANGER}[ERROR]{UI.RESET} {e} (continuing in degraded mode)")

if __name__ == "__main__":
    try:
        main()
    finally:
        # 🔗 Shutdown Bridge on exit
        if BRIDGE_AVAILABLE:
            bridge.bridge_shutdown()
            print("[BRIDGE] C++ IPC Bridge shutdown — Python Brain disconnected")
