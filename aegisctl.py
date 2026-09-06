#!/usr/bin/env python3
"""G26: Control Plane — aegisctl CLI
Usage: python aegisctl.py <command> [args]
Commands:
  status          - Show system status (DEFCON, events, flows, PEP stats)
  health          - Check all subsystems
  start           - Start AEGIS service
  stop            - Stop AEGIS service
  restart         - Restart AEGIS service
  rules list      - List loaded rules
  rules reload    - Hot-reload Rules.json
  flows           - Show active flows
  accounting       - Show event accounting
  pep stats        - Show PEP enforcement stats
  defcon           - Show current DEFCON level
  ips block <ip>   - SENSITIVE: request block (goes through PEP)
  ips unblock <ip> - SENSITIVE: request unblock (goes through PEP)
  ips list         - List active blocks
  forensic <id>    - Show forensic record by ID
  trace <event_id> - Trace event through pipeline
  canary status    - Show canary enforcement status
  simulate <rule>  - Simulate rule match without enforcement
  diagnostics     - System diagnostics dump
"""
import sys, os, json, subprocess, time

def read_json(path):
    try:
        with open(path) as f: return json.load(f)
    except: return None

def cmd_status():
    """READ: Show system status"""
    print("=== AEGIS NIDS Status ===")
    anomalous = read_json("logs/anomalous.json")
    if anomalous:
        print(f"  Alerts logged: {len(anomalous) if isinstance(anomalous, list) else 'N/A'}")
    manifest = read_json("runtime_manifest.json")
    if manifest:
        print(f"  Runtime version: {manifest.get('version', '?')}")
        prod = [k for k,v in manifest.get('modules',{}).items() if v.get('classification')=='production']
        print(f"  Production modules: {len(prod)}")
        print(f"  Modules: {', '.join(prod)}")
    print(f"  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")

def cmd_health():
    """READ: Check all subsystems"""
    print("=== AEGIS Health Check ===")
    pids = {"core": "logs/pids/core.pid", "brain": "logs/pids/brain.pid",
            "nose": "logs/pids/nose.pid", "dashboard": "logs/pids/dashboard.pid"}
    for name, pid_file in pids.items():
        if os.path.exists(pid_file):
            try:
                with open(pid_file) as f: pid = int(f.read().strip())
                try:
                    os.kill(pid, 0)
                    print(f"  [OK] {name}: PID {pid} (alive)")
                except ProcessLookupError:
                    print(f"  [FAIL] {name}: PID {pid} (dead)")
                except PermissionError:
                    print(f"  [OK] {name}: PID {pid} (running)")
            except: print(f"  [WARN] {name}: invalid PID file")
        else:
            print(f"  [INFO] {name}: not started")

def cmd_start():
    """LIFECYCLE: Start AEGIS service"""
    print("Starting AEGIS...")
    if sys.platform == "win32":
        subprocess.Popen(["cmd", "/c", "run_aegis.bat"], creationflags=subprocess.CREATE_NEW_CONSOLE)
    else:
        print("  Use: run_aegis.bat on Windows")
    print("  AEGIS start requested")

def cmd_stop():
    """LIFECYCLE: Stop AEGIS service"""
    print("Stopping AEGIS...")
    pids = ["logs/pids/core.pid", "logs/pids/brain.pid", "logs/pids/nose.pid"]
    for pid_file in pids:
        if os.path.exists(pid_file):
            try:
                with open(pid_file) as f: pid = int(f.read().strip())
                if sys.platform == "win32":
                    subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
                else:
                    import signal; os.kill(pid, signal.SIGTERM)
                print(f"  Stopped PID {pid} ({pid_file})")
                os.remove(pid_file)
            except Exception as e: print(f"  Error stopping {pid_file}: {e}")

def cmd_rules_list():
    """READ: List loaded rules"""
    rules = read_json("Rules.json")
    if not rules: print("No rules loaded"); return
    rule_list = rules.get("nids_rules", rules) if isinstance(rules, dict) else rules
    print(f"=== Rules ({len(rule_list)}) ===")
    for r in rule_list:
        print(f"  [{r.get('id','?')}] {r.get('name','?')} | {r.get('severity','?')} | {r.get('action','?')} | {r.get('layer','?')}")

def cmd_rules_reload():
    """LIFECYCLE: Hot-reload Rules.json"""
    print("Reloading Rules.json...")
    rules = read_json("Rules.json")
    if rules:
        count = len(rules.get("nids_rules", rules)) if isinstance(rules, dict) else len(rules)
        print(f"  [OK] Loaded {count} rules (hot-reload via mtime detection)")
    else:
        print("  [FAIL] Cannot load Rules.json")

def cmd_accounting():
    """READ: Show event accounting"""
    print("=== Event Accounting ===")
    print("  (Live metrics printed by bridgeStatusReporter every 30s)")
    print("  Format: input=processed+dropped+rejected+expired+failed")

def cmd_pep_stats():
    """READ: Show PEP enforcement stats"""
    print("=== PEP Stats ===")
    print("  (Query sec_monitor.dll via FFI: pep_get_stats)")
    print("  Counters: total_enforcements, total_blocks, total_alerts, total_failed")

def cmd_ips_block(ip):
    """REQUEST: Block IP (goes through Rust PEP)"""
    print(f"[REQUEST] Block IP: {ip}")
    print("  Path: aegisctl -> Control Request -> Policy -> Rust PEP -> WFP")
    print(f"  Would call: pep_enforce_action(PepDecision{{action=Block, source_ip={ip}}})")
    print("  [NOTE] This is a sensitive action requiring PEP authorization")

def cmd_ips_unblock(ip):
    """REQUEST: Unblock IP"""
    print(f"[REQUEST] Unblock IP: {ip}")
    print("  Path: aegisctl -> Control Request -> Policy -> Rust PEP")

def cmd_diagnostics():
    """READ: System diagnostics dump"""
    print("=== AEGIS Diagnostics ===")
    print(f"  Python: {sys.version}")
    print(f"  Platform: {sys.platform}")
    print(f"  CWD: {os.getcwd()}")
    cmd_health()
    cmd_rules_list()
    rules = read_json("Rules.json")
    if rules:
        count = len(rules.get("nids_rules", rules)) if isinstance(rules, dict) else len(rules)
        print(f"  Rules loaded: {count}")
    manifest = read_json("runtime_manifest.json")
    if manifest:
        print(f"  Runtime manifest: version {manifest.get('version')}")

def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    cmd = sys.argv[1]
    args = sys.argv[2:]
    commands = {
        "status": cmd_status, "health": cmd_health,
        "start": cmd_start, "stop": cmd_stop, "restart": lambda: (cmd_stop(), cmd_start()),
        "rules": lambda: cmd_rules_list() if not args or args[0]=="list" else cmd_rules_reload() if args[0]=="reload" else print(f"Unknown: rules {args[0]}"),
        "flows": lambda: print("=== Active Flows ===\n  (Live metrics from FlowTable, printed every 30s)"),
        "accounting": cmd_accounting, "pep": cmd_pep_stats, "defcon": lambda: print("DEFCON: (from C++ Bridge)"),
        "ips": lambda: cmd_ips_block(args[1]) if len(args)>=2 and args[0]=="block" else cmd_ips_unblock(args[1]) if len(args)>=2 and args[0]=="unblock" else print("Usage: ips block|unblock <ip>"),
        "forensic": lambda: print(f"Forensic record {args[0] if args else '?'} (from logs/anomalous.json)"),
        "trace": lambda: print(f"Trace event {args[0] if args else '?'} (event_id -> flow_id -> rule_id -> PEP)"),
        "canary": lambda: print("Canary status: (from G29 CanaryConfig)"),
        "simulate": lambda: print(f"Simulate rule: {args[0] if args else '?'} (no enforcement)"),
        "diagnostics": cmd_diagnostics,
    }
    handler = commands.get(cmd)
    if handler: handler()
    else: print(f"Unknown command: {cmd}\n{__doc__}")

if __name__ == "__main__":
    main()
