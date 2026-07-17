"""
AEGIS NIDS — CLI Daemon Manager
================================
ควบคุมระบบ NIDS ในรูปแบบ daemon/service ผ่าน command line

Commands:
  start       — Start all NIDS subsystems as background processes
  stop        — Stop all NIDS subsystems gracefully
  restart     — Restart all subsystems (stop + start)
  status      — Show running status of all subsystems
  rules       — Reload rules without restarting (hot-reload)
  logs        — Tail logs/anomalous.json in real-time
  health      — Check system health (CPU, memory, packet drop rate)
  install     — Install as Windows Service (optional)
  uninstall   — Uninstall Windows Service

Usage:
  python aegis_daemon.py start
  python aegis_daemon.py status
  python aegis_daemon.py stop

Design Principles:
  - Daemon ทำงาน background (ไม่ต้องเปิด cmd หลายหน้าต่าง)
  - PID files เก็บใน logs/ เพื่อ track processes
  - Graceful shutdown ด้วย SIGTERM (Windows: taskkill)
  - Hot-reload rules โดยไม่ restart engine (Rules.json mtime check)
"""
import os
import sys
import json
import time
import signal
import subprocess
import psutil  # pip install psutil
from pathlib import Path
from datetime import datetime

# =====================================================================
# CONFIGURATION
# =====================================================================

BASE_DIR = Path(__file__).parent.resolve()
LOGS_DIR = BASE_DIR / "logs"
PID_DIR = LOGS_DIR / "pids"
LOG_FILE = LOGS_DIR / "anomalous.json"
DAEMON_LOG = LOGS_DIR / "daemon.log"

SUBSYSTEMS = [
    {
        "name": "core",
        "description": "AEGIS Core (Zig) — NIDS engine + 5 threads",
        "start_cmd": "zig build run",
        "stop_pattern": "aegis-nids.exe",
        "pid_file": "core.pid",
    },
    {
        "name": "brain",
        "description": "AEGIS Brain (Python) — Tier-2/3 regex + IPS",
        "start_cmd": "python windows_brain.py",
        "stop_pattern": "windows_brain.py",
        "pid_file": "brain.pid",
    },
    {
        "name": "dashboard",
        "description": "AEGIS Dashboard (Python) — TUI log viewer",
        "start_cmd": "python Dashboard.py",
        "stop_pattern": "Dashboard.py",
        "pid_file": "dashboard.pid",
    },
    {
        "name": "nose",
        "description": "AEGIS Nose (Go) — Goroutines-based perf monitor",
        "start_cmd": "go run windows_perf.go",
        "stop_pattern": "windows_perf",
        "pid_file": "nose.pid",
    },
    {
        "name": "mouth",
        "description": "AEGIS Mouth (Rust) — DEFCON display",
        "start_cmd": "rustc windows_sec_monitor.rs -o windows_sec_monitor.exe && windows_sec_monitor.exe",
        "stop_pattern": "windows_sec_monitor.exe",
        "pid_file": "mouth.pid",
    },
]


# =====================================================================
# UTILITIES
# =====================================================================

class UI:
    GREEN = '\033[92;1m'
    YELLOW = '\033[93;1m'
    RED = '\033[91;1m'
    CYAN = '\033[96;1m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def ensure_dirs():
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    PID_DIR.mkdir(parents=True, exist_ok=True)


def log(msg, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    print(line)
    try:
        with open(DAEMON_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def write_pid(name, pid):
    pid_file = PID_DIR / f"{name}.pid"
    pid_file.write_text(str(pid), encoding="utf-8")


def read_pid(name):
    pid_file = PID_DIR / f"{name}.pid"
    if not pid_file.exists():
        return None
    try:
        return int(pid_file.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


def clear_pid(name):
    pid_file = PID_DIR / f"{name}.pid"
    if pid_file.exists():
        pid_file.unlink()


def is_process_running(pid):
    if not pid:
        return False
    try:
        return psutil.Process(pid).is_running()
    except psutil.NoSuchProcess:
        return False
    except Exception:
        return False


def find_processes_by_pattern(pattern):
    """หา processes ที่มี pattern ใน command line"""
    matching = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = " ".join(proc.info['cmdline'] or [])
            if pattern.lower() in cmdline.lower():
                matching.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return matching


# =====================================================================
# COMMANDS
# =====================================================================

def cmd_start(args):
    """เริ่มระบบ NIDS ทั้งหมดใน background"""
    ensure_dirs()

    # Truncate log file
    LOG_FILE.write_text("", encoding="utf-8")

    log("=" * 60)
    log("Starting AEGIS NIDS daemon — all subsystems")
    log("=" * 60)

    # Build Rust FFI ก่อน (Zig ต้องการ)
    log("Building Rust FFI (sec_monitor.dll)...")
    result = subprocess.run(
        ["cargo", "build", "--release"],
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log(f"Rust build failed: {result.stderr}", "ERROR")
        return False
    log("Rust FFI build OK")

    # Start each subsystem
    started = 0
    for sub in SUBSYSTEMS:
        name = sub["name"]
        # Check if already running
        pid = read_pid(name)
        if pid and is_process_running(pid):
            log(f"  [{name}] already running (PID {pid}) — skip")
            started += 1
            continue

        log(f"  [{name}] starting: {sub['start_cmd']}")
        try:
            # Start in background, no window
            kwargs = {
                "cwd": BASE_DIR,
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "creationflags": subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
            }
            proc = subprocess.Popen(
                sub["start_cmd"],
                shell=True,
                **kwargs,
            )
            write_pid(name, proc.pid)
            log(f"  [{name}] started (PID {proc.pid})")
            started += 1
            time.sleep(1)  # stagger startup
        except Exception as e:
            log(f"  [{name}] FAILED to start: {e}", "ERROR")

    log(f"=" * 60)
    log(f"Started {started}/{len(SUBSYSTEMS)} subsystems.")
    log(f"Use 'python aegis_daemon.py status' to check.")
    log(f"=" * 60)
    return True


def cmd_stop(args):
    """หยุดระบบ NIDS ทั้งหมด"""
    log("=" * 60)
    log("Stopping AEGIS NIDS daemon...")
    log("=" * 60)

    stopped = 0
    for sub in SUBSYSTEMS:
        name = sub["name"]
        # Try PID file first
        pid = read_pid(name)
        if pid and is_process_running(pid):
            log(f"  [{name}] stopping PID {pid}...")
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except psutil.TimeoutExpired:
                    proc.kill()
                stopped += 1
            except psutil.NoSuchProcess:
                pass
            clear_pid(name)
            continue

        # Fallback: find by pattern
        procs = find_processes_by_pattern(sub["stop_pattern"])
        for proc in procs:
            log(f"  [{name}] stopping PID {proc.pid} (pattern match)...")
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except psutil.TimeoutExpired:
                    proc.kill()
                stopped += 1
            except psutil.NoSuchProcess:
                pass
        clear_pid(name)

    log(f"Stopped {stopped} processes.")
    return True


def cmd_restart(args):
    """Restart ระบบทั้งหมด"""
    cmd_stop(args)
    time.sleep(2)
    cmd_start(args)


def cmd_status(args):
    """แสดงสถานะระบบทั้งหมด"""
    print(f"\n{UI.CYAN}{'=' * 70}{UI.RESET}")
    print(f"{UI.CYAN}  AEGIS NIDS — Daemon Status{UI.RESET}")
    print(f"{UI.CYAN}{'=' * 70}{UI.RESET}")
    print(f"  {'SUBSYSTEM':<15} {'STATUS':<10} {'PID':<8} {'DESCRIPTION'}")
    print(f"  {'-' * 65}")

    running_count = 0
    for sub in SUBSYSTEMS:
        name = sub["name"]
        pid = read_pid(name)
        status = "RUNNING" if (pid and is_process_running(pid)) else "STOPPED"
        color = UI.GREEN if status == "RUNNING" else UI.RED
        pid_str = str(pid) if pid else "-"
        print(f"  {name:<15} {color}{status:<10}{UI.RESET} {pid_str:<8} {sub['description']}")
        if status == "RUNNING":
            running_count += 1

    print(f"\n  {running_count}/{len(SUBSYSTEMS)} subsystems running")

    # Show log stats
    if LOG_FILE.exists():
        try:
            line_count = sum(1 for _ in open(LOG_FILE, encoding="utf-8"))
            size_kb = LOG_FILE.stat().st_size / 1024
            print(f"  Log file: {line_count} entries, {size_kb:.1f} KB")
        except Exception:
            pass

    print(f"{UI.CYAN}{'=' * 70}{UI.RESET}\n")


def cmd_rules(args):
    """Hot-reload rules (just touch Rules.json mtime to trigger brain reload)"""
    rules_file = BASE_DIR / "Rules.json"
    if not rules_file.exists():
        log(f"Rules file not found: {rules_file}", "ERROR")
        return False

    # Touch the file to update mtime
    os.utime(rules_file, None)
    log("Rules.json touched — Brain will auto-reload within 1 second")
    log(f"Rules file: {rules_file}")
    log(f"File size: {rules_file.stat().st_size} bytes")
    return True


def cmd_logs(args):
    """Tail logs/anomalous.json in real-time"""
    print(f"{UI.CYAN}Tailing {LOG_FILE} (Ctrl+C to exit)...{UI.RESET}\n")
    if not LOG_FILE.exists():
        print(f"{UI.YELLOW}Log file does not exist yet — start the daemon first.{UI.RESET}")
        return

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            # Seek to end
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    try:
                        entry = json.loads(line.strip())
                        ts = entry.get("timestamp", "?")
                        attack = entry.get("attack_type", "Unknown")
                        policy = entry.get("policy", "ALERT").upper()
                        source = entry.get("source", "?")
                        color = UI.RED if policy in ("BLOCK", "DROP") else UI.YELLOW
                        print(f"{color}[{ts}] {source} | {attack} | {policy}{UI.RESET}")
                    except json.JSONDecodeError:
                        print(line.strip())
                else:
                    time.sleep(0.5)
    except KeyboardInterrupt:
        print(f"\n{UI.YELLOW}Stopped tailing logs.{UI.RESET}")


def cmd_health(args):
    """ตรวจสถานะสุขภาพระบบ"""
    print(f"\n{UI.CYAN}{'=' * 60}{UI.RESET}")
    print(f"{UI.CYAN}  AEGIS NIDS — System Health Check{UI.RESET}")
    print(f"{UI.CYAN}{'=' * 60}{UI.RESET}")

    # Process health
    print(f"\n{UI.BOLD}Process Status:{UI.RESET}")
    for sub in SUBSYSTEMS:
        name = sub["name"]
        pid = read_pid(name)
        if pid and is_process_running(pid):
            try:
                proc = psutil.Process(pid)
                cpu = proc.cpu_percent(interval=0.1)
                mem = proc.memory_info().rss / 1024 / 1024
                print(f"  {name:<15} {UI.GREEN}OK{UI.RESET}    PID={pid:<6} CPU={cpu:.1f}%  MEM={mem:.1f}MB")
            except psutil.NoSuchProcess:
                print(f"  {name:<15} {UI.RED}DEAD{UI.RESET}   PID={pid}")
        else:
            print(f"  {name:<15} {UI.RED}DOWN{UI.RESET}")

    # System health
    print(f"\n{UI.BOLD}System Resources:{UI.RESET}")
    print(f"  CPU Usage   : {psutil.cpu_percent(interval=0.5):.1f}%")
    mem = psutil.virtual_memory()
    print(f"  Memory      : {mem.percent:.1f}% used ({mem.used / 1024**3:.1f} GB / {mem.total / 1024**3:.1f} GB)")
    print(f"  Disk        : {psutil.disk_usage('/').percent:.1f}% used")

    # Network stats
    try:
        net = psutil.net_io_counters()
        print(f"\n{UI.BOLD}Network (since boot):{UI.RESET}")
        print(f"  Packets sent     : {net.packets_sent:,}")
        print(f"  Packets received : {net.packets_recv:,}")
        print(f"  Bytes sent       : {net.bytes_sent / 1024**2:.1f} MB")
        print(f"  Bytes received   : {net.bytes_recv / 1024**2:.1f} MB")
        if hasattr(net, 'errin'):
            print(f"  Errors in/out    : {net.errin}/{net.errout}")
            print(f"  Drops in/out     : {net.dropin}/{net.dropout}")
    except Exception:
        pass

    # Log stats
    if LOG_FILE.exists():
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
            blocks = sum(1 for l in lines if '"policy": "Block"' in l or '"policy": "Drop"' in l)
            print(f"\n{UI.BOLD}Threat Log:{UI.RESET}")
            print(f"  Total alerts : {len(lines)}")
            print(f"  Blocks/Drops : {blocks}")
        except Exception:
            pass

    print(f"{UI.CYAN}{'=' * 60}{UI.RESET}\n")


def cmd_install(args):
    """Install as Windows Service (placeholder — requires pywin32)"""
    print(f"{UI.YELLOW}Windows Service installation not yet implemented.{UI.RESET}")
    print(f"To run as a service, you can use NSSM (Non-Sucking Service Manager):")
    print(f"  nssm install AegisNIDS python {Path(__file__).name} start")
    print(f"  nssm start AegisNIDS")
    print(f"\nOr use Windows Task Scheduler to run at startup.")


def cmd_uninstall(args):
    """Uninstall Windows Service (placeholder)"""
    print(f"{UI.YELLOW}Windows Service uninstall not yet implemented.{UI.RESET}")
    print(f"  nssm stop AegisNIDS")
    print(f"  nssm remove AegisNIDS confirm")


def cmd_help(args):
    """แสดง help"""
    print(f"""
{UI.CYAN}AEGIS NIDS — Daemon Manager{UI.RESET}

{UI.BOLD}Usage:{UI.RESET}
  python aegis_daemon.py <command> [options]

{UI.BOLD}Commands:{UI.RESET}
  {UI.GREEN}start{UI.RESET}      Start all NIDS subsystems in background
  {UI.GREEN}stop{UI.RESET}       Stop all subsystems
  {UI.GREEN}restart{UI.RESET}    Restart all subsystems
  {UI.GREEN}status{UI.RESET}     Show running status of all subsystems
  {UI.GREEN}rules{UI.RESET}      Hot-reload Rules.json (touch mtime → Brain auto-reloads)
  {UI.GREEN}logs{UI.RESET}       Tail logs/anomalous.json in real-time
  {UI.GREEN}health{UI.RESET}     System health check (CPU, memory, network, threats)
  {UI.GREEN}install{UI.RESET}    Install as Windows Service (placeholder)
  {UI.GREEN}uninstall{UI.RESET}  Uninstall Windows Service (placeholder)
  {UI.GREEN}help{UI.RESET}       Show this help

{UI.BOLD}Examples:{UI.RESET}
  python aegis_daemon.py start
  python aegis_daemon.py status
  python aegis_daemon.py logs
  python aegis_daemon.py health
  python aegis_daemon.py stop

{UI.BOLD}Log files:{UI.RESET}
  {LOGS_DIR / "anomalous.json"} — threat alerts (JSONL)
  {LOGS_DIR / "daemon.log"} — daemon manager log
  {PID_DIR} — PID files for tracking processes
""")


# =====================================================================
# MAIN
# =====================================================================

COMMANDS = {
    "start": cmd_start,
    "stop": cmd_stop,
    "restart": cmd_restart,
    "status": cmd_status,
    "rules": cmd_rules,
    "logs": cmd_logs,
    "health": cmd_health,
    "install": cmd_install,
    "uninstall": cmd_uninstall,
    "help": cmd_help,
}


def main():
    if len(sys.argv) < 2:
        cmd_help(None)
        return 1

    cmd = sys.argv[1].lower()
    args = sys.argv[2:]

    if cmd not in COMMANDS:
        print(f"{UI.RED}Unknown command: {cmd}{UI.RESET}")
        cmd_help(None)
        return 1

    # Handle SIGINT gracefully for `logs` command
    try:
        result = COMMANDS[cmd](args)
        return 0 if result is None or result else 1
    except KeyboardInterrupt:
        print(f"\n{UI.YELLOW}Interrupted.{UI.RESET}")
        return 130
    except Exception as e:
        log(f"Error: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
