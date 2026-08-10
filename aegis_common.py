"""
AEGIS NIDS — Shared Library (v1)
=================================
โค้ดร่วมระหว่าง aegis_console และ aegis_daemon
ทั้งสอง module import จากไฟล์นี้ — ไม่ duplicate code

Contents:
  - Constants (paths, filenames, subsystem definitions)
  - Process helpers (is_running, stop, find_by_pattern)
  - Mouth build logic (rustc → cargo fallback)
  - Auto-rebuild detection (mtime check)
  - Windows VT100 enable
  - Optional psutil detection
"""
import os
import sys
import time
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

# =====================================================================
# OPTIONAL DEPENDENCIES
# =====================================================================
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import ctypes
    _KERNEL32 = ctypes.windll.kernel32
except Exception:
    _KERNEL32 = None


# =====================================================================
# PATHS & CONSTANTS
# =====================================================================
BASE_DIR = Path(__file__).parent.resolve()
LOGS_DIR = BASE_DIR / "logs"
PID_DIR = LOGS_DIR / "pids"
LOG_FILE = LOGS_DIR / "anomalous.json"
DAEMON_LOG = LOGS_DIR / "daemon.log"
RULES_FILE = BASE_DIR / "Rules.json"

MOUTH_EXE = "windows_sec_monitor.exe"
MOUTH_SRC = "windows_sec_monitor.rs"

# =====================================================================
# SUBSYSTEM DEFINITIONS (single source of truth)
# =====================================================================
SUBSYSTEMS = [
    {
        "key": "bridge",
        "name": "Bridge",
        "description": "AEGIS Bridge (C++) — IPC hub + Packet Parser + DEFCON",
        "start_cmd": "build\\Release\\aegis_bridge.exe",
        "stop_pattern": "aegis_bridge.exe",
        "pid_file": "bridge.pid",
        "binary_path": "build/Release/aegis_bridge.exe",
        "source_paths": ["bridge/aegis_ipc.cpp", "bridge/aegis_bridge_main.cpp"],
        "window_title": "AEGIS BRIDGE (C++)",
    },
    {
        "key": "core",
        "name": "Core",
        "description": "AEGIS Core (Zig) — Tier-1 Aho-Corasick pattern matching",
        "start_cmd": "zig build run",
        "stop_pattern": "aegis-nids.exe",
        "pid_file": "core.pid",
        "binary_path": None,
        "source_paths": ["nids_main.zig"],
        "window_title": "AEGIS CORE (Zig)",
    },
    {
        "key": "brain",
        "name": "Brain",
        "description": "AEGIS Brain (Python) — Tier-2 regex + IPS policy enforcement",
        "start_cmd": "python windows_brain.py",
        "stop_pattern": "windows_brain.py",
        "pid_file": "brain.pid",
        "binary_path": "windows_brain.py",
        "source_paths": ["windows_brain.py", "Rules.json"],
        "window_title": "AEGIS BRAIN (Python)",
    },
    {
        "key": "mouth",
        "name": "Mouth",
        "description": "AEGIS Mouth (Rust) — Tier-3 behavioral validation + DEFCON display",
        "start_cmd": "windows_sec_monitor.exe",
        "stop_pattern": "windows_sec_monitor.exe",
        "pid_file": "mouth.pid",
        "binary_path": "windows_sec_monitor.exe",
        "source_paths": ["windows_sec_monitor.rs"],
        "window_title": "AEGIS MOUTH (Rust)",
    },
    {
        "key": "nose",
        "name": "Nose",
        "description": "AEGIS Nose (Go) — 3 Goroutines perf monitor + DEFCON calculator",
        "start_cmd": "go run windows_perf.go",
        "stop_pattern": "windows_perf",
        "pid_file": "nose.pid",
        "binary_path": None,
        "source_paths": ["windows_perf.go"],
        "window_title": "AEGIS NOSE (Go)",
    },
    {
        "key": "dashboard",
        "name": "Dashboard",
        "description": "AEGIS Dashboard (Rust egui) — Web UI Command Center",
        "start_cmd": "aegis_dashboard\\target\\release\\aegis_dashboard.exe",
        "stop_pattern": "aegis_dashboard.exe",
        "pid_file": "dashboard.pid",
        "binary_path": "aegis_dashboard/target/release/aegis_dashboard.exe",
        "source_paths": ["aegis_dashboard/src/main.rs"],
        "window_title": "AEGIS DASHBOARD (Rust)",
    },
]


# =====================================================================
# WINDOWS VT100
# =====================================================================
def enable_windows_vt100():
    """Enable ANSI escape sequences on Windows 10/11 CMD."""
    if os.name != 'nt' or _KERNEL32 is None:
        return
    try:
        handle = _KERNEL32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        _KERNEL32.GetConsoleMode(handle, ctypes.byref(mode))
        if not (mode.value & 0x0004):  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
            _KERNEL32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


# =====================================================================
# PROCESS HELPERS
# =====================================================================
_process_cache = {"timestamp": 0.0, "running": set()}

def _refresh_process_cache(max_age=1.0):
    """Refresh the set of running process names. Cached for max_age seconds."""
    now = time.time()
    if now - _process_cache["timestamp"] < max_age:
        return
    running = set()
    if PSUTIL_AVAILABLE:
        for proc in psutil.process_iter(['name']):
            try:
                name = proc.info['name']
                if name:
                    running.add(name.lower())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    elif os.name == 'nt':
        try:
            result = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n'):
                parts = line.split(',')
                if len(parts) >= 2:
                    pname = parts[0].strip('"').lower()
                    if pname:
                        running.add(pname)
        except Exception:
            pass
    _process_cache["running"] = running
    _process_cache["timestamp"] = now


def is_process_running(process_name, use_cache=True):
    """Check if a process is running.
    Args:
        process_name: e.g. "windows_sec_monitor.exe"
        use_cache: True = cached (fast), False = direct (accurate for stop)
    """
    if use_cache:
        _refresh_process_cache()
        return process_name.lower() in _process_cache["running"]

    # Direct check (no cache)
    if PSUTIL_AVAILABLE:
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'].lower() == process_name.lower():
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False
    elif os.name == 'nt':
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"IMAGENAME eq {process_name}"],
                capture_output=True, text=True, timeout=5
            )
            return process_name.lower() in result.stdout.lower()
        except Exception:
            return False
    return False


def is_pid_running(pid):
    """Check if a PID is still alive."""
    if not pid:
        return False
    if PSUTIL_AVAILABLE:
        try:
            return psutil.Process(pid).is_running()
        except psutil.NoSuchProcess:
            return False
        except Exception:
            return False
    else:
        if os.name == 'nt':
            try:
                result = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}"],
                    capture_output=True, text=True, timeout=5
                )
                return str(pid) in result.stdout
            except Exception:
                return False
        else:
            try:
                os.kill(pid, 0)
                return True
            except ProcessLookupError:
                return False
            except Exception:
                return False


def stop_process(process_name):
    """Force-stop a process by name."""
    if os.name == 'nt':
        subprocess.run(
            ["taskkill", "/F", "/IM", process_name],
            capture_output=True, timeout=5
        )
    else:
        subprocess.run(
            ["pkill", "-f", process_name],
            capture_output=True, timeout=5
        )


def stop_pid(pid):
    """Gracefully stop a process by PID, then force-kill if needed."""
    import signal
    if PSUTIL_AVAILABLE:
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()
            return True
        except psutil.NoSuchProcess:
            return True
        except Exception:
            return False
    else:
        if os.name == 'nt':
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, timeout=5)
            return True
        else:
            try:
                os.kill(pid, signal.SIGTERM)
                time.sleep(1)
                return True
            except ProcessLookupError:
                return True
            except Exception:
                return False


def find_processes_by_pattern(pattern):
    """Find processes matching a pattern in their command line."""
    if PSUTIL_AVAILABLE:
        matching = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = " ".join(proc.info['cmdline'] or [])
                if pattern.lower() in cmdline.lower():
                    matching.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return matching
    return []


def get_process_cpu_mem(pid):
    """Get CPU% and memory MB for a PID. Returns (cpu, mem) or (None, None)."""
    if not PSUTIL_AVAILABLE:
        return None, None
    try:
        proc = psutil.Process(pid)
        cpu = proc.cpu_percent(interval=0.1)
        mem = proc.memory_info().rss / 1024 / 1024
        return cpu, mem
    except Exception:
        return None, None


# =====================================================================
# PID FILE HELPERS
# =====================================================================
def ensure_dirs():
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    PID_DIR.mkdir(parents=True, exist_ok=True)


def write_pid(name, pid):
    ensure_dirs()
    (PID_DIR / f"{name}.pid").write_text(str(pid), encoding="utf-8")


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


# =====================================================================
# AUTO-REBUILD DETECTION
# =====================================================================
def needs_rebuild(src_name, exe_name):
    """Check if source file is newer than binary."""
    src_path = BASE_DIR / src_name
    exe_path = BASE_DIR / exe_name
    if not src_path.exists():
        return False
    if not exe_path.exists():
        return True
    return src_path.stat().st_mtime > exe_path.stat().st_mtime


def subsystem_needs_rebuild(sub):
    """Check if any source for a subsystem is newer than its binary."""
    binary_path = sub.get("binary_path")
    source_paths = sub.get("source_paths", [])
    if not binary_path or not source_paths:
        return True
    bin_full = BASE_DIR / binary_path
    if not bin_full.exists():
        return True
    bin_mtime = bin_full.stat().st_mtime
    for src in source_paths:
        src_full = BASE_DIR / src
        if src_full.exists() and src_full.stat().st_mtime > bin_mtime:
            return True
    return False


# =====================================================================
# MOUTH BUILD (3-layer fallback)
# =====================================================================
def build_mouth_exe(verbose=True, force=False):
    """Build windows_sec_monitor.exe — rustc → cargo --bin → cargo lib + rustc.

    Args:
        verbose: Print status messages
        force: Force rebuild even if exe exists

    Returns:
        True if exe exists after build attempt
    """
    exe_path = BASE_DIR / MOUTH_EXE

    # Auto-rebuild check
    if not force and exe_path.exists():
        if needs_rebuild(MOUTH_SRC, MOUTH_EXE):
            if verbose:
                _log("REBUILD", f"{MOUTH_SRC} is newer than {MOUTH_EXE}")
            force = True
        else:
            if verbose:
                _log("OK", f"{MOUTH_EXE} up-to-date")
            return True

    # Remove stale exe
    if force and exe_path.exists():
        try:
            exe_path.unlink()
        except PermissionError:
            if verbose:
                _log("WARN", "Cannot remove running exe — stop Mouth first")
            return True

    if verbose:
        _log("BUILD", f"{MOUTH_SRC} -> {MOUTH_EXE}")

    # Method 1: rustc (fastest)
    if _try_rustc(verbose):
        return True

    # Method 2: cargo --bin
    if _try_cargo_bin(verbose):
        return True

    # Method 3: cargo lib + rustc
    if _try_cargo_lib_then_rustc(verbose):
        return True

    if verbose:
        _log("FAIL", f"Could not build {MOUTH_EXE}")
    return False


def _try_rustc(verbose):
    try:
        result = subprocess.run(
            ["rustc", MOUTH_SRC, "-o", MOUTH_EXE],
            cwd=str(BASE_DIR), capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and (BASE_DIR / MOUTH_EXE).exists():
            if verbose:
                _log("OK", "Built with rustc")
            return True
        elif verbose:
            err = (result.stderr.strip().split('\n')[-1][:120]
                   if result.stderr.strip() else "unknown")
            _log("WARN", f"rustc: {err}")
    except FileNotFoundError:
        if verbose:
            _log("WARN", "rustc not in PATH")
    except Exception as e:
        if verbose:
            _log("WARN", f"rustc: {e}")
    return False


def _try_cargo_bin(verbose):
    if verbose:
        _log("BUILD", "Trying cargo --bin...")
    try:
        result = subprocess.run(
            ["cargo", "build", "--release", "--manifest-path", "Cargo.toml", "--bin", "windows_sec_monitor"],
            cwd=str(BASE_DIR), capture_output=True, text=True, timeout=120
        )
        cargo_exe = BASE_DIR / "target" / "release" / MOUTH_EXE
        if result.returncode == 0 and cargo_exe.exists():
            shutil.copy2(cargo_exe, BASE_DIR / MOUTH_EXE)
            if verbose:
                _log("OK", "Built with cargo")
            return True
        elif verbose:
            err = (result.stderr.strip().split('\n')[-1][:120]
                   if result.stderr.strip() else "unknown")
            _log("WARN", f"cargo: {err}")
    except FileNotFoundError:
        if verbose:
            _log("WARN", "cargo not in PATH")
    except Exception as e:
        if verbose:
            _log("WARN", f"cargo: {e}")
    return False


def _try_cargo_lib_then_rustc(verbose):
    if verbose:
        _log("BUILD", "Trying cargo lib + rustc...")
    try:
        subprocess.run(
            ["cargo", "build", "--release", "--manifest-path", "Cargo.toml"],
            cwd=str(BASE_DIR), capture_output=True, text=True, timeout=120
        )
        result = subprocess.run(
            ["rustc", MOUTH_SRC, "-o", MOUTH_EXE],
            cwd=str(BASE_DIR), capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and (BASE_DIR / MOUTH_EXE).exists():
            if verbose:
                _log("OK", "Built with rustc (after cargo lib)")
            return True
    except Exception:
        pass
    return False


# =====================================================================
# LOGGING
# =====================================================================
def _log(level, msg):
    """Simple colored log for build output."""
    colors = {
        "OK": "\033[92m", "BUILD": "\033[96;1m", "WARN": "\033[93m",
        "FAIL": "\033[91;1m", "REBUILD": "\033[93;1m", "INFO": "\033[96m",
    }
    reset = "\033[0m"
    color = colors.get(level, "")
    print(f"  {color}[{level}]{reset} {msg}")


def daemon_log(msg, level="INFO"):
    """Append to daemon log file."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    try:
        ensure_dirs()
        with open(DAEMON_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    return line


# =====================================================================
# RULES HELPERS
# =====================================================================
def load_rules():
    """Load Rules.json. Returns dict with 'nids_rules' key."""
    if not RULES_FILE.exists():
        data = {"nids_rules": []}
        save_rules(data)
        return data
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "nids_rules" not in data:
                data["nids_rules"] = []
            return data
    except (json.JSONDecodeError, OSError) as e:
        return {"nids_rules": []}


def save_rules(data):
    """Save Rules.json."""
    import json
    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
