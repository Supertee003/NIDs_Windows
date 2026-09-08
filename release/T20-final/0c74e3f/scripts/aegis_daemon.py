"""
AEGIS NIDS -- CLI Daemon Manager v2.0
======================================
Daemon manager with watchdog auto-restart

Commands:
  start       -- Start all NIDS subsystems as background processes
  stop        -- Stop all NIDS subsystems gracefully
  restart     -- Restart all subsystems (stop + start)
  status      -- Show running status of all subsystems
  watchdog    -- Run as persistent watchdog (monitor + auto-restart crashed)
  rules       -- Reload rules without restarting (hot-reload)
  logs        -- Tail logs/anomalous.json in real-time
  health      -- Check system health (CPU, memory, packet drop rate)
  install     -- Install as Windows Service (optional)
  uninstall   -- Uninstall Windows Service

Usage:
  python aegis_daemon.py start
  python aegis_daemon.py status
  python aegis_daemon.py watchdog
  python aegis_daemon.py stop

Design Principles (v2.0):
  - Best practice: use pre-compiled binaries + CLI args (same as run_aegis.bat v2.2)
  - Watchdog: persistent process that monitors + auto-restarts crashed subsystems
  - Stale PID cleanup on start: detect dead PIDs and clean up before launch
  - PID files in logs/pids/ for process tracking
  - Graceful shutdown with SIGTERM (Windows: taskkill)
  - Hot-reload rules without restart (Rules.json mtime check)
"""
import os
import sys
import json
import time
import signal
import subprocess
import threading
from pathlib import Path
from datetime import datetime

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# =====================================================================
# CONFIGURATION
# =====================================================================

_SCRIPT_DIR = Path(__file__).parent.resolve()
# Auto-detect project root (one level up from scripts/)
if (_SCRIPT_DIR / ".." / "core").exists() or (_SCRIPT_DIR / ".." / "brain").exists():
    BASE_DIR = (_SCRIPT_DIR / "..").resolve()
else:
    BASE_DIR = _SCRIPT_DIR  # fallback: assume already in root
LOGS_DIR = BASE_DIR / "logs"
PID_DIR = LOGS_DIR / "pids"
LOG_FILE = LOGS_DIR / "anomalous.json"
DAEMON_LOG = LOGS_DIR / "daemon.log"
WATCHDOG_PID_FILE = PID_DIR / "watchdog.pid"

# Best practice: match run_aegis.bat v2.2 -- 5 core subsystems
# Use pre-compiled binaries + CLI args (no build-on-start)
SUBSYSTEMS = [
    {
        "name": "bridge",
        "description": "Bridge (C++) -- IPC hub + Packet Parser + DEFCON",
        # Best practice: use pre-compiled binary from build/Release/
        "start_cmd": str(BASE_DIR / "build" / "Release" / "aegis_bridge.exe"),
        "is_shell": False,
        "stop_pattern": "aegis_bridge.exe",
        "pid_file": "bridge.pid",
        "required": True,
    },
    {
        "name": "core",
        "description": "Core (Zig) -- Tier-1 Aho-Corasick pattern matching",
        # Best practice: use zig-out/bin/ binary
        "start_cmd": str(BASE_DIR / "zig-out" / "bin" / "aegis-nids.exe"),
        "is_shell": False,
        "stop_pattern": "aegis-nids.exe",
        "pid_file": "core.pid",
        "required": True,
    },
    {
        "name": "brain",
        "description": "Brain (Python) -- Tier-2 regex + IPS policy enforcement",
        "start_cmd": None,  # special: uses sys.executable
        "start_args": [str(BASE_DIR / "brain" / "windows_brain.py")],
        "is_shell": False,
        "stop_pattern": "windows_brain.py",
        "pid_file": "brain.pid",
        "required": True,
    },
    {
        "name": "nose",
        "description": "Nose (Go) -- 3 Goroutines perf monitor + DEFCON",
        # Best practice: use pre-compiled dist/aegis-nose.exe + CLI args
        "start_cmd": str(BASE_DIR / "dist" / "aegis-nose.exe"),
        "start_args": [
            "--log", str(BASE_DIR / "logs" / "anomalous.json"),
            "--refresh", "1000",
        ],
        "is_shell": False,
        "stop_pattern": "aegis-nose.exe",
        "pid_file": "nose.pid",
        "required": True,
    },
    {
        "name": "mouth",
        "description": "Mouth (Rust) -- behavioral validation + DEFCON display",
        # Best practice: use pre-compiled dist/windows_sec_monitor.exe + CLI args
        "start_cmd": str(BASE_DIR / "dist" / "windows_sec_monitor.exe"),
        "start_args": [
            "--log", str(BASE_DIR / "logs" / "anomalous.json"),
            "--refresh", "1000",
        ],
        "is_shell": False,
        "stop_pattern": "windows_sec_monitor.exe",
        "pid_file": "mouth.pid",
        "required": True,
    },
]

# Watchdog settings
WATCHDOG_INTERVAL = 5       # seconds between health checks
WATCHDOG_MAX_RESTARTS = 3   # max restart attempts per subsystem per hour
WATCHDOG_RESTART_WINDOW = 3600  # 1 hour sliding window


# =====================================================================
# UTILITIES
# =====================================================================

class UI:
    GREEN = '\033[92;1m'
    YELLOW = '\033[93;1m'
    RED = '\033[91m'
    CYAN = '\033[96;1m'
    DIM = '\033[2m'
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
    ensure_dirs()
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


def clear_all_pids():
    """Remove all stale PID files."""
    if PID_DIR.exists():
        for f in PID_DIR.glob("*.pid"):
            f.unlink()


def is_process_running(pid):
    if not pid:
        return False
    if not PSUTIL_AVAILABLE:
        # Fallback: check via tasklist on Windows
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                capture_output=True, text=True, timeout=5
            )
            return str(pid) in result.stdout
        except Exception:
            return False
    try:
        proc = psutil.Process(pid)
        return proc.is_running()
    except psutil.NoSuchProcess:
        return False
    except Exception:
        return False


def cleanup_stale_pids():
    """Check all PID files and remove stale ones (process no longer running).
    Returns list of (name, old_pid) that were cleaned up."""
    cleaned = []
    for sub in SUBSYSTEMS:
        name = sub["name"]
        pid = read_pid(name)
        if pid is not None:
            if is_process_running(pid):
                # Verify the PID actually belongs to our subsystem
                if PSUTIL_AVAILABLE:
                    try:
                        proc = psutil.Process(pid)
                        cmdline = " ".join(proc.cmdline()).lower()
                        pattern = sub["stop_pattern"].lower()
                        if pattern not in cmdline and name != "brain":
                            # PID recycled -- different process owns this PID now
                            log(f"  [{name}] PID {pid} recycled (different process) -- cleaning", "WARN")
                            clear_pid(name)
                            cleaned.append((name, pid))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            else:
                # Process no longer running -- stale PID
                log(f"  [{name}] stale PID {pid} (process dead) -- cleaning", "WARN")
                clear_pid(name)
                cleaned.append((name, pid))
    return cleaned


def find_processes_by_pattern(pattern):
    """Find processes matching pattern in command line."""
    if not PSUTIL_AVAILABLE:
        return []
    matching = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = " ".join(proc.info['cmdline'] or [])
            if pattern.lower() in cmdline.lower():
                matching.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return matching


def find_pid_by_pattern(pattern):
    """Find first PID matching pattern."""
    procs = find_processes_by_pattern(pattern)
    return procs[0].pid if procs else None


# =====================================================================
# START SUBSYSTEM
# =====================================================================

def start_subsystem(sub):
    """Start a single subsystem. Returns (success, pid)."""
    name = sub["name"]

    # Check if already running
    pid = read_pid(name)
    if pid and is_process_running(pid):
        log(f"  [{name}] already running (PID {pid}) -- skip")
        return True, pid

    # Also check by pattern (in case PID file is missing but process is running)
    existing_pid = find_pid_by_pattern(sub["stop_pattern"])
    if existing_pid:
        log(f"  [{name}] already running (PID {existing_pid}, found by pattern) -- updating PID file")
        write_pid(name, existing_pid)
        return True, existing_pid

    # Build command
    if name == "brain":
        # Special: Python process
        cmd = [sys.executable] + sub.get("start_args", [])
    else:
        cmd = [sub["start_cmd"]] + sub.get("start_args", [])

    # Check binary exists (skip for brain which uses sys.executable)
    if name != "brain" and not os.path.exists(sub["start_cmd"]):
        log(f"  [{name}] binary not found: {sub['start_cmd']} -- skip", "WARN")
        return False, None

    log(f"  [{name}] starting: {' '.join(cmd)}")
    try:
        kwargs = {
            "cwd": str(BASE_DIR),
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if os.name == 'nt':
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        proc = subprocess.Popen(cmd, **kwargs)
        write_pid(name, proc.pid)
        log(f"  [{name}] started (PID {proc.pid})")
        return True, proc.pid
    except Exception as e:
        log(f"  [{name}] FAILED to start: {e}", "ERROR")
        clear_pid(name)
        return False, None


# =====================================================================
# STOP SUBSYSTEM
# =====================================================================

def stop_subsystem(sub):
    """Stop a single subsystem. Returns True if stopped."""
    name = sub["name"]
    stopped = False

    # Try PID file first
    pid = read_pid(name)
    if pid and is_process_running(pid):
        log(f"  [{name}] stopping PID {pid}...")
        try:
            if PSUTIL_AVAILABLE:
                proc = psutil.Process(pid)
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except psutil.TimeoutExpired:
                    proc.kill()
            else:
                subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                              capture_output=True, timeout=5)
            stopped = True
        except Exception:
            pass
        clear_pid(name)

    # Fallback: find by pattern
    if not stopped:
        procs = find_processes_by_pattern(sub["stop_pattern"])
        for proc in procs:
            log(f"  [{name}] stopping PID {proc.pid} (pattern match)...")
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except psutil.TimeoutExpired:
                    proc.kill()
                stopped = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    if not stopped:
        # Last resort: taskkill by image name on Windows
        if os.name == 'nt':
            exe_name = sub["stop_pattern"]
            result = subprocess.run(
                ["taskkill", "/F", "/IM", exe_name],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                stopped = True

    clear_pid(name)
    return stopped


# =====================================================================
# COMMANDS
# =====================================================================

def cmd_start(args):
    """Start all NIDS subsystems in background."""
    ensure_dirs()

    skip_build = "--skip-build" in args

    log("=" * 60)
    log("Starting AEGIS NIDS daemon -- all 5 subsystems")
    log("=" * 60)

    # Phase 0: Cleanup stale PIDs
    cleaned = cleanup_stale_pids()
    if cleaned:
        log(f"  Cleaned {len(cleaned)} stale PID file(s)")

    # Phase 1: Build (optional, can be skipped with --skip-build)
    if not skip_build:
        # Build Rust FFI (Zig needs it)
        log("Building Rust FFI (sec_monitor.dll)...")
        result = subprocess.run(
            ["cargo", "build", "--release", "--manifest-path", str(BASE_DIR / "shield" / "Cargo.toml")],
            cwd=str(BASE_DIR), capture_output=True, text=True,
        )
        if result.returncode != 0:
            log(f"Rust build failed: {result.stderr}", "ERROR")
            log("Use --skip-build to skip this step", "WARN")
        else:
            log("Rust FFI build OK")

        # Build C++ IPC Bridge
        log("Building C++ IPC Bridge (aegis_ipc.dll)...")
        result = subprocess.run(
            ["cmake", "-B", "build", "-S", "bridge", "-DCMAKE_BUILD_TYPE=Release"],
            cwd=str(BASE_DIR), capture_output=True, text=True,
        )
        if result.returncode == 0:
            result = subprocess.run(
                ["cmake", "--build", "build", "--config", "Release"],
                cwd=str(BASE_DIR), capture_output=True, text=True,
            )
        if result.returncode != 0:
            log(f"C++ build failed: {result.stderr}", "ERROR")
            log("Use --skip-build to skip this step", "WARN")
        else:
            log("C++ IPC Bridge build OK")

    # Phase 2: Start each subsystem
    started = 0
    for sub in SUBSYSTEMS:
        success, pid = start_subsystem(sub)
        if success:
            started += 1
        time.sleep(1)  # stagger startup

    log("=" * 60)
    log(f"Started {started}/{len(SUBSYSTEMS)} subsystems.")
    log(f"Use 'python aegis_daemon.py status' to check.")
    log(f"Use 'python aegis_daemon.py watchdog' to enable auto-restart.")
    log("=" * 60)
    return True


def cmd_stop(args):
    """Stop all NIDS subsystems + watchdog."""
    force = "--force" in args or "-f" in args

    log("=" * 60)
    log("Stopping AEGIS NIDS daemon...")
    log("=" * 60)

    # Stop watchdog first
    watchdog_pid = read_pid("watchdog")
    if watchdog_pid and is_process_running(watchdog_pid):
        log(f"  [watchdog] stopping PID {watchdog_pid}...")
        try:
            if PSUTIL_AVAILABLE:
                proc = psutil.Process(watchdog_pid)
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except psutil.TimeoutExpired:
                    proc.kill()
            else:
                subprocess.run(["taskkill", "/PID", str(watchdog_pid), "/F"],
                              capture_output=True, timeout=5)
            log("  [watchdog] stopped")
        except Exception as e:
            log(f"  [watchdog] stop failed: {e}", "WARN")
        clear_pid("watchdog")

    # Stop subsystems in reverse order (Bridge last -- it's IPC hub)
    stopped = 0
    for sub in reversed(SUBSYSTEMS):
        name = sub["name"]
        if stop_subsystem(sub):
            log(f"  [{name}] stopped")
            stopped += 1
        else:
            log(f"  [{name}] not running")

    if force:
        log("[FORCE] Killing any remaining AEGIS processes...")
        for exe in ["aegis-nids.exe", "aegis_bridge.exe", "windows_sec_monitor.exe", "aegis-nose.exe"]:
            if os.name == 'nt':
                subprocess.run(["taskkill", "/F", "/IM", exe], capture_output=True)
        # Kill brain
        for proc in find_processes_by_pattern("windows_brain"):
            try:
                proc.kill()
            except Exception:
                pass

    # Wait and verify
    time.sleep(2)
    still_running = 0
    for sub in SUBSYSTEMS:
        pid = find_pid_by_pattern(sub["stop_pattern"])
        if pid:
            still_running += 1

    log(f"Stopped {stopped} processes.")
    if still_running > 0:
        log(f"{still_running} process(es) still running. Use --force to kill.", "WARN")
    else:
        log("All AEGIS processes stopped.")

    clear_all_pids()
    return True


def cmd_restart(args):
    """Restart all subsystems."""
    cmd_stop(args)
    time.sleep(2)
    cmd_start(args)


def cmd_status(args):
    """Show running status of all subsystems."""
    print(f"\n{UI.CYAN}{'=' * 72}{UI.RESET}")
    print(f"{UI.CYAN}  AEGIS NIDS -- Daemon Status (v2.0){UI.RESET}")
    print(f"{UI.CYAN}{'=' * 72}{UI.RESET}")
    print(f"  {'SUBSYSTEM':<12} {'STATUS':<10} {'PID':<8} {'UPTIME':<10} {'DESCRIPTION'}")
    print(f"  {'-' * 68}")

    running_count = 0
    for sub in SUBSYSTEMS:
        name = sub["name"]
        # Check by PID file first, then by pattern
        pid = read_pid(name)
        running = pid and is_process_running(pid)
        if not running:
            # Try pattern match
            pid = find_pid_by_pattern(sub["stop_pattern"])
            running = pid is not None
            if running:
                write_pid(name, pid)  # update PID file

        status = "RUNNING" if running else "STOPPED"
        color = UI.GREEN if running else UI.RED
        pid_str = str(pid) if pid else "-"

        # Calculate uptime
        uptime_str = "-"
        if running and pid and PSUTIL_AVAILABLE:
            try:
                proc = psutil.Process(pid)
                create_time = proc.create_time()
                uptime_secs = time.time() - create_time
                if uptime_secs > 3600:
                    uptime_str = f"{uptime_secs/3600:.1f}h"
                elif uptime_secs > 60:
                    uptime_str = f"{uptime_secs/60:.0f}m"
                else:
                    uptime_str = f"{uptime_secs:.0f}s"
            except Exception:
                pass

        print(f"  {name:<12} {color}{status:<10}{UI.RESET} {pid_str:<8} {uptime_str:<10} {sub['description']}")
        if running:
            running_count += 1

    # Watchdog status
    watchdog_pid = read_pid("watchdog")
    watchdog_running = watchdog_pid and is_process_running(watchdog_pid)
    wd_status = f"{UI.GREEN}RUNNING{UI.RESET}" if watchdog_running else f"{UI.DIM}OFF{UI.RESET}"
    wd_pid = str(watchdog_pid) if watchdog_running else "-"
    print(f"  {'watchdog':<12} {wd_status:<18} {wd_pid:<8}")

    print(f"\n  {running_count}/{len(SUBSYSTEMS)} subsystems running")

    if running_count == len(SUBSYSTEMS):
        print(f"  {UI.GREEN}*** AEGIS FULLY OPERATIONAL ***{UI.RESET}")
    elif running_count > 0:
        print(f"  {UI.YELLOW}*** AEGIS PARTIALLY RUNNING ***{UI.RESET}")
    else:
        print(f"  {UI.RED}*** AEGIS STOPPED ***{UI.RESET}")

    # Log stats
    if LOG_FILE.exists():
        try:
            line_count = sum(1 for _ in open(LOG_FILE, encoding="utf-8"))
            size_kb = LOG_FILE.stat().st_size / 1024
            print(f"\n  {UI.DIM}Log: {line_count} entries, {size_kb:.1f} KB{UI.RESET}")
        except Exception:
            pass

    print(f"{UI.CYAN}{'=' * 72}{UI.RESET}\n")


# =====================================================================
# WATCHDOG -- persistent process monitor with auto-restart
# =====================================================================

class Watchdog:
    """Persistent watchdog that monitors subsystems and auto-restarts crashed ones."""

    def __init__(self):
        self._running = True
        self._restart_counts = {}  # name -> list of restart timestamps
        self._lock = threading.Lock()

    def _record_restart(self, name):
        """Record a restart attempt. Returns True if within limits."""
        now = time.time()
        with self._lock:
            if name not in self._restart_counts:
                self._restart_counts[name] = []
            # Prune old entries outside the window
            self._restart_counts[name] = [
                t for t in self._restart_counts[name]
                if now - t < WATCHDOG_RESTART_WINDOW
            ]
            if len(self._restart_counts[name]) >= WATCHDOG_MAX_RESTARTS:
                return False  # too many restarts
            self._restart_counts[name].append(now)
            return True

    def _check_and_restart(self):
        """Check all subsystems, restart any that crashed."""
        for sub in SUBSYSTEMS:
            name = sub["name"]
            pid = read_pid(name)
            running = pid and is_process_running(pid)

            if not running:
                # Also check by pattern
                existing_pid = find_pid_by_pattern(sub["stop_pattern"])
                if existing_pid:
                    write_pid(name, existing_pid)
                    continue

                # Process is dead -- try to restart
                if self._record_restart(name):
                    log(f"[WATCHDOG] {name} crashed! Auto-restarting...", "WARN")
                    success, new_pid = start_subsystem(sub)
                    if success:
                        log(f"[WATCHDOG] {name} restarted (PID {new_pid})")
                    else:
                        log(f"[WATCHDOG] {name} restart FAILED", "ERROR")
                else:
                    log(f"[WATCHDOG] {name} exceeded max restarts "
                        f"({WATCHDOG_MAX_RESTARTS}/{WATCHDOG_RESTART_WINDOW}s) -- giving up", "ERROR")

    def run(self):
        """Main watchdog loop."""
        log("=" * 60)
        log("[WATCHDOG] AEGIS NIDS Watchdog started")
        log(f"[WATCHDOG] Check interval: {WATCHDOG_INTERVAL}s")
        log(f"[WATCHDOG] Max restarts: {WATCHDOG_MAX_RESTARTS}/{WATCHDOG_RESTART_WINDOW}s")
        log("=" * 60)

        # Write watchdog PID
        write_pid("watchdog", os.getpid())

        # Setup signal handlers for graceful shutdown
        def handle_signal(signum, frame):
            log(f"[WATCHDOG] Received signal {signum} -- shutting down")
            self._running = False

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        while self._running:
            try:
                self._check_and_restart()
            except Exception as e:
                log(f"[WATCHDOG] Error in check loop: {e}", "ERROR")

            # Sleep in small increments to respond to signals quickly
            for _ in range(WATCHDOG_INTERVAL * 10):
                if not self._running:
                    break
                time.sleep(0.1)

        log("[WATCHDOG] Watchdog stopped")
        clear_pid("watchdog")


def cmd_watchdog(args):
    """Run as persistent watchdog -- monitor and auto-restart crashed subsystems."""
    # Check if watchdog is already running
    existing_pid = read_pid("watchdog")
    if existing_pid and is_process_running(existing_pid):
        print(f"{UI.YELLOW}Watchdog already running (PID {existing_pid}){UI.RESET}")
        print(f"Stop it first: python aegis_daemon.py stop")
        return True

    # Start subsystems first if not running
    running = 0
    for sub in SUBSYSTEMS:
        pid = read_pid(sub["name"])
        if pid and is_process_running(pid):
            running += 1
        elif find_pid_by_pattern(sub["stop_pattern"]):
            running += 1

    if running == 0:
        print(f"{UI.CYAN}No subsystems running -- starting all first...{UI.RESET}")
        cmd_start(args)
        time.sleep(2)

    # Run watchdog
    wd = Watchdog()
    try:
        wd.run()
    except KeyboardInterrupt:
        print(f"\n{UI.YELLOW}Watchdog interrupted.{UI.RESET}")
        wd._running = False
    return True


def cmd_watchdog_bg(args):
    """Start watchdog in background (detached process)."""
    existing_pid = read_pid("watchdog")
    if existing_pid and is_process_running(existing_pid):
        print(f"{UI.YELLOW}Watchdog already running (PID {existing_pid}){UI.RESET}")
        return True

    # Launch self as background watchdog
    cmd = [sys.executable, str(Path(__file__)), "watchdog"]
    kwargs = {
        "cwd": str(BASE_DIR),
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if os.name == 'nt':
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    proc = subprocess.Popen(cmd, **kwargs)
    time.sleep(1)

    if is_process_running(proc.pid):
        write_pid("watchdog", proc.pid)
        print(f"{UI.GREEN}Watchdog started in background (PID {proc.pid}){UI.RESET}")
    else:
        print(f"{UI.RED}Watchdog failed to start{UI.RESET}")
    return True


# =====================================================================
# OTHER COMMANDS
# =====================================================================

def cmd_rules(args):
    """Hot-reload rules (touch Rules.json mtime to trigger brain reload)."""
    rules_file = BASE_DIR / "config" / "Rules.json"
    if not rules_file.exists():
        log(f"Rules file not found: {rules_file}", "ERROR")
        return False

    os.utime(rules_file, None)
    log("Rules.json touched -- Brain will auto-reload within 1 second")
    log(f"Rules file: {rules_file}")
    log(f"File size: {rules_file.stat().st_size} bytes")
    return True


def cmd_logs(args):
    """Tail logs/anomalous.json in real-time."""
    print(f"{UI.CYAN}Tailing {LOG_FILE} (Ctrl+C to exit)...{UI.RESET}\n")
    if not LOG_FILE.exists():
        print(f"{UI.YELLOW}Log file does not exist yet -- start the daemon first.{UI.RESET}")
        return

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
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
    """Check system health."""
    print(f"\n{UI.CYAN}{'=' * 60}{UI.RESET}")
    print(f"{UI.CYAN}  AEGIS NIDS -- System Health Check{UI.RESET}")
    print(f"{UI.CYAN}{'=' * 60}{UI.RESET}")

    if not PSUTIL_AVAILABLE:
        print(f"\n  {UI.YELLOW}psutil not available -- limited health check{UI.RESET}")
        # Basic check via tasklist
        for sub in SUBSYSTEMS:
            pid = find_pid_by_pattern(sub["stop_pattern"])
            status = f"{UI.GREEN}OK{UI.RESET}" if pid else f"{UI.RED}DOWN{UI.RESET}"
            print(f"  {sub['name']:<12} {status}")
        return True

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
                print(f"  {name:<12} {UI.GREEN}OK{UI.RESET}    PID={pid:<6} CPU={cpu:.1f}%  MEM={mem:.1f}MB")
            except psutil.NoSuchProcess:
                print(f"  {name:<12} {UI.RED}DEAD{UI.RESET}   PID={pid}")
        else:
            # Try pattern
            existing_pid = find_pid_by_pattern(sub["stop_pattern"])
            if existing_pid:
                print(f"  {name:<12} {UI.YELLOW}OK*{UI.RESET}   PID={existing_pid:<6} (PID file stale)")
            else:
                print(f"  {name:<12} {UI.RED}DOWN{UI.RESET}")

    # System health
    print(f"\n{UI.BOLD}System Resources:{UI.RESET}")
    print(f"  CPU Usage   : {psutil.cpu_percent(interval=0.5):.1f}%")
    mem = psutil.virtual_memory()
    print(f"  Memory      : {mem.percent:.1f}% used ({mem.used / 1024**3:.1f} GB / {mem.total / 1024**3:.1f} GB)")
    try:
        disk_path = 'C:\\' if os.name == 'nt' else '/'
        print(f"  Disk        : {psutil.disk_usage(disk_path).percent:.1f}% used")
    except Exception:
        print(f"  Disk        : unavailable")

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
    """Install as Windows Service (placeholder -- requires nssm or pywin32)."""
    print(f"{UI.YELLOW}Windows Service installation options:{UI.RESET}")
    print(f"\n  Option 1: NSSM (Non-Sucking Service Manager)")
    print(f"    nssm install AegisNIDS python {Path(__file__).name} watchdog")
    print(f"    nssm start AegisNIDS")
    print(f"\n  Option 2: Windows Task Scheduler")
    print(f"    Create task to run at startup:")
    print(f"    python {Path(__file__).name} watchdog")
    print(f"\n  Option 3: pywin32 service (requires pywin32)")
    print(f"    Not yet implemented.")


def cmd_uninstall(args):
    """Uninstall Windows Service."""
    print(f"{UI.YELLOW}Windows Service uninstall:{UI.RESET}")
    print(f"  nssm stop AegisNIDS")
    print(f"  nssm remove AegisNIDS confirm")


def cmd_help(args):
    """Show help."""
    print(f"""
{UI.CYAN}AEGIS NIDS -- Daemon Manager v2.0{UI.RESET}

{UI.BOLD}Usage:{UI.RESET}
  python aegis_daemon.py <command> [options]

{UI.BOLD}Commands:{UI.RESET}
  {UI.GREEN}start{UI.RESET}       Start all NIDS subsystems in background
  {UI.GREEN}stop{UI.RESET}        Stop all subsystems + watchdog
  {UI.GREEN}restart{UI.RESET}     Restart all subsystems
  {UI.GREEN}status{UI.RESET}      Show running status of all subsystems
  {UI.GREEN}watchdog{UI.RESET}    Run as persistent watchdog (monitor + auto-restart)
  {UI.GREEN}watchdog-bg{UI.RESET} Start watchdog in background
  {UI.GREEN}rules{UI.RESET}       Hot-reload Rules.json (touch mtime -> Brain auto-reloads)
  {UI.GREEN}logs{UI.RESET}        Tail logs/anomalous.json in real-time
  {UI.GREEN}health{UI.RESET}      System health check (CPU, memory, network, threats)
  {UI.GREEN}install{UI.RESET}     Install as Windows Service (placeholder)
  {UI.GREEN}uninstall{UI.RESET}   Uninstall Windows Service
  {UI.GREEN}help{UI.RESET}        Show this help

{UI.BOLD}Options:{UI.RESET}
  --skip-build    Skip build step (use existing binaries)
  --force / -f    Force kill (no graceful timeout)

{UI.BOLD}Examples:{UI.RESET}
  python aegis_daemon.py start              # Start all subsystems
  python aegis_daemon.py watchdog           # Start + monitor (foreground)
  python aegis_daemon.py watchdog-bg        # Start + monitor (background)
  python aegis_daemon.py status             # Check status
  python aegis_daemon.py health             # Health check
  python aegis_daemon.py logs               # Tail threat log
  python aegis_daemon.py stop               # Stop everything

{UI.BOLD}Log files:{UI.RESET}
  {LOGS_DIR / "anomalous.json"} -- threat alerts (JSONL)
  {LOGS_DIR / "daemon.log"} -- daemon manager log
  {PID_DIR} -- PID files for tracking processes
""")


# =====================================================================
# MAIN
# =====================================================================

COMMANDS = {
    "start": cmd_start,
    "stop": cmd_stop,
    "restart": cmd_restart,
    "status": cmd_status,
    "watchdog": cmd_watchdog,
    "watchdog-bg": cmd_watchdog_bg,
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
