"""
AEGIS NIDS -- Command Control Center v8.0
==========================================
Refactored from v7.2 -- eliminate overlapping menus & display

Key changes from v7.2:
  - Flat main menu: START/STOP/RESTART/STATUS are top-level (no nested menu_system)
  - Removed duplicate menu_status() -- STATUS is inline in main
  - Merged DAEMON into main: watchdog toggle is top-level, daemon-only cmds in submenu
  - Removed duplicate _avail() markers in Test Suite
  - Health menu: Dashboard merged into single health view (no separate sub-option)
  - Mouth launch uses --log --refresh consistently (best practice)
  - Clean section grouping: SYSTEM / CONTROL / ANALYSIS

Usage:
  python aegis_console.py
"""
import os
import sys
import json
import subprocess
import time
import shutil
from datetime import datetime

# -- Optional imports --
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import aegis_graph
    AEGIS_GRAPH_AVAILABLE = True
except ImportError:
    AEGIS_GRAPH_AVAILABLE = False

# -- Script directory (needed early for path resolution) --
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# -- Auto-detect Project Root --
_markers = ["core", "brain", "mouth", "build.zig"]
PROJECT_ROOT = None
for _m in _markers:
    if os.path.exists(os.path.join(SCRIPT_DIR, "..", _m)):
        PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
        break
if PROJECT_ROOT is None:
    for _m in _markers:
        if os.path.exists(os.path.join(SCRIPT_DIR, _m)):
            PROJECT_ROOT = SCRIPT_DIR
            break
if PROJECT_ROOT is None:
    PROJECT_ROOT = SCRIPT_DIR  # fallback
os.chdir(PROJECT_ROOT)

# -- Constants (absolute paths based on PROJECT_ROOT) --
RULES_FILE = os.path.join(PROJECT_ROOT, "config", "Rules.json")
GRAPH_HTML_FILE = os.path.join(PROJECT_ROOT, "threat_graph.html")
LOG_FILE = os.path.join(PROJECT_ROOT, "logs", "anomalous.json")

# -- C++ IPC Bridge integration --
_shared_paths = [
    os.path.join(SCRIPT_DIR, "..", "shared"),
    os.path.join(PROJECT_ROOT, "shared"),
    os.path.join(SCRIPT_DIR, "shared"),
]
for _sp in _shared_paths:
    _abs_sp = os.path.abspath(_sp)
    if _abs_sp not in sys.path:
        sys.path.insert(0, _abs_sp)
try:
    import aegis_bridge_ctypes as bridge
    BRIDGE_AVAILABLE = True
except ImportError:
    BRIDGE_AVAILABLE = False


# =====================================================================
# ANSI Colors
# =====================================================================
class C:
    RST = '\033[0m'
    BLD = '\033[1m'
    DIM = '\033[2m'
    RED = '\033[91m';    GRN = '\033[92m';    YEL = '\033[93m'
    BLU = '\033[94m';    MAG = '\033[95m';    CYN = '\033[96m';    WHT = '\033[97m'
    BRED = '\033[91;1m'; BGRN = '\033[92;1m'; BYEL = '\033[93;1m'
    BBLU = '\033[94;1m'; BCYN = '\033[96;1m'
    DC1 = '\033[91;1m'; DC2 = '\033[91m'; DC3 = '\033[93;1m'
    DC4 = '\033[93m';   DC5 = '\033[92m'

DEFCON_COLORS = {1: C.DC1, 2: C.DC2, 3: C.DC3, 4: C.DC4, 5: C.DC5}
DEFCON_LABELS = {1: "COCKED PISTOL", 2: "DOUBLE TAKE", 3: "ROUND HOUSE",
                 4: "FAST PACE", 5: "FADE OUT"}
DEFCON_SCALE = {1: "■" * 5, 2: "■" * 4 + "□", 3: "■" * 3 + "□" * 2,
                4: "■" * 2 + "□" * 3, 5: "■" + "□" * 4}

# -- Subsystem definitions (5 core subsystems) --
SUBSYSTEMS = [
    {"name": "BRIDGE", "lang": "C++",   "exe": "aegis_bridge.exe",        "py": None},
    {"name": "CORE",   "lang": "Zig",   "exe": "aegis-nids.exe",          "py": None},
    {"name": "BRAIN",  "lang": "Python","exe": "python.exe",              "py": "windows_brain.py"},
    {"name": "NOSE",   "lang": "Go",    "exe": "aegis-nose.exe",        "py": None},
    {"name": "MOUTH",  "lang": "Rust",  "exe": "windows_sec_monitor.exe", "py": None},
]

# Best practice CLI args for Nose & Mouth (matching run_aegis.bat)
NOSE_CLI_ARGS = []  # NOSE v5D.0 uses bubbletea TUI, no CLI flags needed
MOUTH_CLI_ARGS = ["--log", os.path.join(PROJECT_ROOT, "logs", "anomalous.json"),
                  "--refresh", "1000"]


# =====================================================================
# UTILITY
# =====================================================================

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_timestamp():
    return datetime.now().strftime("%H:%M:%S")

def draw_bar(value, max_val=100, width=20, fill="█", empty="░"):
    ratio = min(max(value / max_val, 0), 1)
    return fill * int(ratio * width) + empty * (width - int(ratio * width))

def input_pause(msg="\n  Press Enter to continue..."):
    input(msg)


# =====================================================================
# SUBSYSTEM STATUS
# =====================================================================

def check_subsystem(sub):
    """Check if subsystem is running -> (running, pid)"""
    exe = sub["exe"]
    py = sub.get("py")

    if PSUTIL_AVAILABLE:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'status']):
            try:
                if proc.info['name'] and exe.lower() in proc.info['name'].lower():
                    if py:
                        cmdline = " ".join(proc.info.get('cmdline') or [])
                        if py.lower() not in cmdline.lower():
                            continue
                    if proc.info['status'] == 'running':
                        return True, proc.info['pid']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    else:
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"IMAGENAME eq {exe}", "/NH"],
                capture_output=True, text=True, timeout=5
            )
            if exe.lower() in result.stdout.lower():
                parts = result.stdout.strip().split()
                pid = parts[1] if len(parts) > 1 else "?"
                return True, pid
        except Exception:
            pass
    return False, None


def get_all_status():
    results = []
    for sub in SUBSYSTEMS:
        running, pid = check_subsystem(sub)
        results.append((sub["name"], sub["lang"], running, pid))
    return results


def get_defcon():
    """Get DEFCON level -- try Bridge IPC first, then fallback to log file."""
    if BRIDGE_AVAILABLE:
        try:
            rc = bridge.bridge_init()
            if rc == 0:
                level = bridge.get_defcon_level()
                label = bridge.get_defcon_label()
                bridge.bridge_shutdown()
                if level is not None:
                    return level, label
        except Exception:
            pass

    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(max(0, f.seek(0, 2) - 8192))
                lines = f.readlines()
                for line in reversed(lines):
                    line = line.strip()
                    if not line or not line.startswith('{'):
                        continue
                    try:
                        entry = json.loads(line)
                        if 'defcon_level' in entry:
                            lvl = entry['defcon_level']
                            lbl = entry.get('defcon_label', DEFCON_LABELS.get(lvl, ''))
                            return lvl, lbl
                    except (json.JSONDecodeError, KeyError):
                        continue
    except Exception:
        pass

    return None, None


# =====================================================================
# HEADER
# =====================================================================

def _is_watchdog_running():
    """Check if watchdog process is running."""
    pid_dir = os.path.join(PROJECT_ROOT, "logs", "pids")
    watchdog_pid_file = os.path.join(pid_dir, "watchdog.pid")
    if not os.path.exists(watchdog_pid_file):
        return False
    try:
        wpid = int(open(watchdog_pid_file).read().strip())
        if PSUTIL_AVAILABLE:
            return psutil.pid_exists(wpid) and psutil.Process(wpid).is_running()
        elif os.name == 'nt':
            result = subprocess.run(["tasklist", "/FI", f"PID eq {wpid}", "/NH"],
                                   capture_output=True, text=True, timeout=5)
            return str(wpid) in result.stdout
    except Exception:
        pass
    return False


def show_header():
    defcon_level, defcon_label = get_defcon()
    if defcon_level:
        dc = DEFCON_COLORS.get(defcon_level, C.RST)
        scale = DEFCON_SCALE.get(defcon_level, "")
        defcon_str = f"{dc}DEFCON {defcon_level} {defcon_label}{C.RST}"
    else:
        defcon_str = f"{C.DIM}DEFCON N/A{C.RST}"

    statuses = get_all_status()
    running = sum(1 for _, _, r, _ in statuses if r)
    total = len(statuses)

    mouth_running = any(name == "MOUTH" and r for name, _, r, _ in statuses)
    mouth_str = f"{C.BGRN}ON{C.RST}" if mouth_running else f"{C.BRED}OFF{C.RST}"

    wd_running = _is_watchdog_running()
    wd_str = f"{C.BGRN}ON{C.RST}" if wd_running else f"{C.DIM}OFF{C.RST}"

    dots = ""
    for name, lang, is_running, pid in statuses:
        dots += f"{C.BGRN}●{C.RST}" if is_running else f"{C.BRED}○{C.RST}"

    print(f"{'═' * 64}")
    print(f'  {C.BLD}{C.CYN}AEGIS NIDS — COMMAND CENTER (v8.0){C.RST}')
    print(f"  {defcon_str}")
    print(f"  Mouth: {mouth_str} | WD: {wd_str} | Active: {C.BLD}{running}/{total}{C.RST}  {dots}")
    print(f"  Time: {C.DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RST}")
    print(f"{'═' * 64}")


# =====================================================================
# SUBSYSTEM LAUNCH / KILL  (unified, best practice)
# =====================================================================

# Window titles matching run_aegis.bat
_WIN_TITLES = {
    "BRIDGE": "AEGIS BRIDGE (C++)",
    "CORE":   "AEGIS CORE (Zig)",
    "BRAIN":  "AEGIS BRAIN (Python)",
    "NOSE":   "AEGIS NOSE (Go)",
    "MOUTH":  "AEGIS MOUTH (Rust)",
}


def _launch_all_subsystems():
    """Launch all 5 subsystems using best practice pattern (matches run_aegis.bat)."""
    # (name, cmd, delay, launch_mode)
    # launch_mode: 'console' = new visible window, 'minimized' = /MIN window, 'tui' = cmd /k
    cmds = [
        ("BRIDGE", [os.path.join(PROJECT_ROOT, "build", "Release", "aegis_bridge.exe")],
         0, 'console'),
        ("CORE",   [os.path.join(PROJECT_ROOT, "zig-out", "bin", "aegis-nids.exe")],
         3, 'console'),
        ("BRAIN",  [sys.executable, os.path.join(PROJECT_ROOT, "brain", "windows_brain.py")],
         6, 'console'),
        # Best practice: pre-compiled binary + --log + --refresh (matches run_aegis.bat)
        ("NOSE",   [os.path.join(PROJECT_ROOT, "dist", "aegis-nose.exe")] + NOSE_CLI_ARGS,
         8, 'minimized'),
        ("MOUTH",  [os.path.join(PROJECT_ROOT, "dist", "windows_sec_monitor.exe")] + MOUTH_CLI_ARGS,
         9, 'tui'),
    ]
    launched = 0
    skipped = 0
    for name, cmd, delay, mode in cmds:
        if delay > 0:
            time.sleep(min(delay, 2))
        exe = cmd[0]
        if not os.path.exists(exe):
            print(f"  {C.YEL}SKIP{C.RST} {name}: {os.path.basename(exe)} not found")
            skipped += 1
            continue
        try:
            kwargs = {"cwd": PROJECT_ROOT}
            if os.name == 'nt':
                if mode == 'minimized':
                    # NOSE: visible minimized window with TUI dashboard
                    title = _WIN_TITLES.get(name, f"AEGIS {name}")
                    cmd_str = f"title {title} & "
                    cmd_str += " ".join(f'"{c}"' if " " in c else c for c in cmd)
                    cmd = ["cmd", "/k", f"start /MIN {cmd_str}"]
                    kwargs["creationflags"] = getattr(subprocess, 'CREATE_NEW_CONSOLE', 0)
                else:
                    # console + tui: wrap with cmd /k + title (survives crash)
                    title = _WIN_TITLES.get(name, f"AEGIS {name}")
                    cmd_str = f"title {title} & "
                    cmd_str += " ".join(f'"{c}"' if " " in c else c for c in cmd)
                    cmd = ["cmd", "/k", cmd_str]
                    kwargs["creationflags"] = getattr(subprocess, 'CREATE_NEW_CONSOLE', 0)
            subprocess.Popen(cmd, **kwargs)
            print(f"  {C.BGRN}OK{C.RST}   {name}: launched ({mode})")
            launched += 1
        except Exception as e:
            print(f"  {C.BRED}FAIL{C.RST} {name}: {e}")
    return launched, skipped


def _kill_all_subsystems():
    """Stop all subsystems (matches stop_aegis.bat order: Brain->Nose->Mouth->Core->Bridge)."""
    # Use stop_aegis.bat if available (canonical source of truth)
    bat = os.path.join(SCRIPT_DIR, "stop_aegis.bat")
    if os.path.exists(bat):
        result = subprocess.run(["cmd", "/c", bat, "--force"],
                                capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            print(f"  {C.BGRN}OK{C.RST} stop_aegis.bat completed")
            return True

    # Fallback: manual kill
    targets = ["aegis-nids.exe", "aegis_bridge.exe", "windows_sec_monitor.exe", "aegis-nose.exe"]
    for exe in targets:
        if os.name == 'nt':
            subprocess.run(["taskkill", "/F", "/IM", exe], capture_output=True)
    if PSUTIL_AVAILABLE:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if 'python' in (proc.info['name'] or '').lower():
                    cmdline = " ".join(proc.info.get('cmdline') or [])
                    if 'windows_brain' in cmdline.lower() or 'aegis_daemon' in cmdline.lower():
                        proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    else:
        for _script in ["windows_brain.py", "aegis_daemon.py"]:
            try:
                subprocess.run(
                    ["wmic", "process", "where", f"commandline like '%{_script}%'", "call", "terminate"],
                    capture_output=True, text=True, timeout=5
                )
            except Exception:
                pass
    return True


def _launch_single_subsystem(name):
    """Launch a single subsystem by name."""
    sub = next((s for s in SUBSYSTEMS if s["name"] == name), None)
    if sub is None:
        print(f"  {C.BRED}[-]{C.RST} Unknown subsystem: {name}")
        return False

    running, pid = check_subsystem(sub)
    if running:
        print(f"  {C.YEL}[!]{C.RST} {name} already running (PID {pid})")
        return True

    # Build command based on subsystem
    if name == "BRIDGE":
        cmd = [os.path.join(PROJECT_ROOT, "build", "Release", "aegis_bridge.exe")]
        mode = 'console'
    elif name == "CORE":
        cmd = [os.path.join(PROJECT_ROOT, "zig-out", "bin", "aegis-nids.exe")]
        mode = 'console'
    elif name == "BRAIN":
        cmd = [sys.executable, os.path.join(PROJECT_ROOT, "brain", "windows_brain.py")]
        mode = 'console'
    elif name == "NOSE":
        cmd = [os.path.join(PROJECT_ROOT, "dist", "aegis-nose.exe")] + NOSE_CLI_ARGS
        mode = 'minimized'
    elif name == "MOUTH":
        cmd = [os.path.join(PROJECT_ROOT, "dist", "windows_sec_monitor.exe")] + MOUTH_CLI_ARGS
        mode = 'tui'
    else:
        print(f"  {C.BRED}[-]{C.RST} No launch config for {name}")
        return False

    exe = cmd[0]
    if not os.path.exists(exe):
        print(f"  {C.YEL}[!]{C.RST} {os.path.basename(exe)} not found")
        return False

    try:
        kwargs = {"cwd": PROJECT_ROOT}
        if os.name == 'nt':
            if mode == 'minimized':
                title = _WIN_TITLES.get(name, f"AEGIS {name}")
                cmd_str = f"title {title} & "
                cmd_str += " ".join(f'"{c}"' if " " in c else c for c in cmd)
                cmd = ["cmd", "/k", f"start /MIN {cmd_str}"]
                kwargs["creationflags"] = getattr(subprocess, 'CREATE_NEW_CONSOLE', 0)
            else:
                title = _WIN_TITLES.get(name, f"AEGIS {name}")
                cmd_str = f"title {title} & "
                cmd_str += " ".join(f'"{c}"' if " " in c else c for c in cmd)
                cmd = ["cmd", "/k", cmd_str]
                kwargs["creationflags"] = getattr(subprocess, 'CREATE_NEW_CONSOLE', 0)
        subprocess.Popen(cmd, **kwargs)
        print(f"  {C.BGRN}OK{C.RST}   {name}: launched ({mode})")
        return True
    except Exception as e:
        print(f"  {C.BRED}FAIL{C.RST} {name}: {e}")
        return False


def _kill_single_subsystem(name):
    """Kill a single subsystem by name."""
    sub = next((s for s in SUBSYSTEMS if s["name"] == name), None)
    if sub is None:
        print(f"  {C.BRED}[-]{C.RST} Unknown subsystem: {name}")
        return

    running, pid = check_subsystem(sub)
    if not running:
        print(f"  {C.YEL}[!]{C.RST} {name} not running")
        return

    exe = sub["exe"]
    if name == "BRAIN" and PSUTIL_AVAILABLE:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if 'python' in (proc.info['name'] or '').lower():
                    cmdline = " ".join(proc.info.get('cmdline') or [])
                    if 'windows_brain' in cmdline.lower():
                        proc.kill()
                        print(f"  {C.BGRN}OK{C.RST} {name} stopped (PID {proc.info['pid']})")
                        return
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    elif name == "BRAIN":
        try:
            subprocess.run(
                ["wmic", "process", "where", "commandline like '%windows_brain.py%'", "call", "terminate"],
                capture_output=True, text=True, timeout=5
            )
            print(f"  {C.BGRN}OK{C.RST} {name} stopped")
            return
        except Exception:
            pass
    else:
        if os.name == 'nt':
            subprocess.run(["taskkill", "/F", "/IM", exe], capture_output=True)
            print(f"  {C.BGRN}OK{C.RST} {name} stopped")
            return


# =====================================================================
# SHOW SUBSYSTEM DETAIL (single source of truth for status display)
# =====================================================================

def show_subsystem_detail():
    """Display subsystem status table — the ONLY place this is rendered."""
    print(f"\n  {C.BLD}SUBSYSTEM STATUS{C.RST}")
    print(f"  {'─' * 62}")
    print(f"  {'NAME':<10} {'LANG':<8} {'STATUS':<10} {'PID':<8} {'MEMORY'}")
    print(f"  {'─' * 62}")
    for sub in SUBSYSTEMS:
        running, pid = check_subsystem(sub)
        if running:
            status_str = f"{C.BGRN}RUNNING{C.RST}"
            pid_str = str(pid) if pid else "?"
            mem_str = ""
            if PSUTIL_AVAILABLE and pid:
                try:
                    proc = psutil.Process(int(pid))
                    mem_str = f"{proc.memory_info().rss / 1024 / 1024:.1f} MB"
                except Exception:
                    pass
        else:
            status_str = f"{C.BRED}STOPPED{C.RST}"
            pid_str = "-"
            mem_str = "-"
        print(f"  {sub['name']:<10} {sub['lang']:<8} {status_str} {pid_str:<8} {mem_str}")
    print(f"  {'─' * 62}")


# =====================================================================
# WATCHDOG (unified — only one place to toggle)
# =====================================================================

def toggle_watchdog():
    """Toggle watchdog on/off — single implementation."""
    daemon_script = os.path.join(SCRIPT_DIR, "aegis_daemon.py")
    if not os.path.exists(daemon_script):
        print(f"\n  {C.BRED}[-]{C.RST} aegis_daemon.py not found")
        input_pause()
        return

    watchdog_running = _is_watchdog_running()

    if watchdog_running:
        print(f"\n  {C.CYN}[WATCHDOG]{C.RST} Stopping watchdog...")
        result = subprocess.run(
            [sys.executable, daemon_script, "stop"],
            capture_output=True, text=True, timeout=15, cwd=SCRIPT_DIR,
        )
        print(f"  {C.BGRN}OK{C.RST} Watchdog stopped")
    else:
        print(f"\n  {C.CYN}[WATCHDOG]{C.RST} Starting watchdog in background...")
        result = subprocess.run(
            [sys.executable, daemon_script, "watchdog-bg"],
            capture_output=True, text=True, timeout=15, cwd=SCRIPT_DIR,
        )
        if result.returncode == 0:
            print(f"  {C.BGRN}OK{C.RST} Watchdog started (auto-restart enabled)")
            print(f"  {C.DIM}Daemon will monitor and restart crashed subsystems{C.RST}")
        else:
            print(f"  {C.BRED}FAIL{C.RST} {result.stderr}")
    input_pause()


# =====================================================================
# 1. MOUTH CONTROL (Rust special handling)
# =====================================================================

def menu_mouth():
    """Mouth Control -- Start/Stop/Rebuild Rust Mouth"""
    while True:
        clear_screen()
        show_header()

        mouth_sub = next((s for s in SUBSYSTEMS if s["name"] == "MOUTH"), None)
        if mouth_sub is None:
            print(f"  {C.BRED}[-]{C.RST} MOUTH subsystem not defined")
            input_pause()
            return
        running, pid = check_subsystem(mouth_sub)

        if running:
            status = f"{C.BGRN}RUNNING{C.RST} (PID {pid})"
        else:
            status = f"{C.BRED}STOPPED{C.RST}"

        print(f"""
  {C.BLD}MOUTH CONTROL (Rust){C.RST}
  {'─' * 50}
  Status: {status}
  {'─' * 50}
  {C.BGRN}1{C.RST}  [START]     เปิด Mouth (with --log --refresh)
  {C.BGRN}2{C.RST}  [STOP]      หยุด Mouth
  {C.BGRN}3{C.RST}  [REBUILD]   คอมไพล์ใหม่ (rustc -O) + start
  {C.BGRN}4{C.RST}  [CARGO]     Build via cargo + start
  {C.YEL}0{C.RST}  [BACK]
""")
        choice = input(f"  {C.BLD}Select (0-4): {C.RST}").strip()

        if choice == '1':
            if running:
                print(f"\n  {C.YEL}[!]{C.RST} Mouth already running (PID {pid})")
            else:
                _launch_single_subsystem("MOUTH")
            input_pause()

        elif choice == '2':
            _kill_single_subsystem("MOUTH")
            input_pause()

        elif choice == '3':
            print(f"\n  {C.CYN}[REBUILD]{C.RST} Compiling Rust Mouth with rustc...")
            _kill_single_subsystem("MOUTH")
            time.sleep(1)

            rs_file = os.path.join(PROJECT_ROOT, "mouth", "windows_sec_monitor.rs")
            if not os.path.exists(rs_file):
                print(f"  {C.BRED}[-]{C.RST} {rs_file} not found")
                input_pause()
                continue

            result = subprocess.run(
                ["rustc", "-O", rs_file, "-o", os.path.join(PROJECT_ROOT, "dist", "windows_sec_monitor.exe")],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                print(f"  {C.BGRN}[OK]{C.RST} Compiled successfully!")
                _launch_single_subsystem("MOUTH")
            else:
                print(f"  {C.BRED}[-]{C.RST} Compile failed:\n{result.stderr}")
            input_pause()

        elif choice == '4':
            print(f"\n  {C.CYN}[CARGO]{C.RST} Building with cargo...")
            _kill_single_subsystem("MOUTH")
            time.sleep(1)

            result = subprocess.run(
                ["cargo", "build", "--release", "--manifest-path", os.path.join(PROJECT_ROOT, "shield", "Cargo.toml")],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                print(f"  {C.BGRN}[OK]{C.RST} cargo build succeeded (shield/sec_monitor.dll)")
                shield_dll = os.path.join(PROJECT_ROOT, "shield", "target", "release", "sec_monitor.dll")
                dist_dir = os.path.join(PROJECT_ROOT, "dist")
                os.makedirs(dist_dir, exist_ok=True)
                if os.path.exists(shield_dll):
                    shutil.copy2(shield_dll, os.path.join(dist_dir, "sec_monitor.dll"))
                    print(f"  {C.BGRN}[OK]{C.RST} Copied sec_monitor.dll -> dist/")
                else:
                    print(f"  {C.YEL}[!]{C.RST} sec_monitor.dll not found in shield/target/release/")
                print(f"  {C.DIM}Note: cargo builds shield/sec_monitor.dll (FFI library){C.RST}")
                print(f"  {C.DIM}Use [REBUILD] to compile the standalone exe{C.RST}")
            else:
                print(f"  {C.BRED}[-]{C.RST} cargo build failed:\n{result.stderr}")
            input_pause()

        elif choice == '0':
            break


# =====================================================================
# 2. RULE MANAGEMENT
# =====================================================================

def load_rules():
    if not os.path.exists(RULES_FILE):
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
        print(f"  {C.BRED}[!]{C.RST} Failed to load rules: {e}")
        return {"nids_rules": []}


def save_rules(data):
    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def menu_rules():
    while True:
        clear_screen()
        show_header()
        rules = load_rules()
        rule_list = rules.get("nids_rules", [])

        print(f"\n  {C.BLD}RULE MANAGEMENT{C.RST}  ({len(rule_list)} rules loaded)")
        print(f"  {'─' * 85}")
        print(f"  {'ID':<8} | {'Layer':<14} | {'Attack Name':<30} | {'Policy':<8} | {'Ports':<10} | {'Proto'}")
        print(f"  {'─' * 85}")

        for r in rule_list:
            if '_comment' in r:
                continue
            policy = r.get('action', 'Alert')
            layer = r.get('layer', '?')
            target_ports = r.get('target_ports', [])
            target_protocols = r.get('target_protocols', [])
            if policy.upper() in ("BLOCK", "DROP"):
                policy_display = f"{C.BRED}{policy}{C.RST}"
            else:
                policy_display = f"{C.BYEL}{policy}{C.RST}"
            ports_str = ",".join(str(p) for p in target_ports) if target_ports else "*"
            proto_str = ",".join(target_protocols) if target_protocols else "*"
            print(f"  {r.get('rule_id', 'N/A'):<8} | {layer:<14} | {r.get('name', 'N/A'):<30} | {policy_display:<17} | {ports_str:<10} | {proto_str}")

        print(f"\n  {C.BLD}Options:{C.RST}")
        print(f"  {C.BGRN}T{C.RST} Toggle  {C.BGRN}A{C.RST} Add  {C.BGRN}D{C.RST} Delete  {C.BGRN}H{C.RST} Hot Reload  {C.YEL}B{C.RST} Back")
        choice = input(f"\n  {C.BLD}Select (T/A/D/H/B): {C.RST}").strip().upper()

        if choice == 'T':
            target_id = input("  Rule ID: ").strip().upper()
            found = False
            for r in rule_list:
                if r.get("rule_id", "").upper() == target_id:
                    current = r.get("action", "Alert")
                    r["action"] = "Block" if current.upper() in ("BLOCK", "DROP") else "Alert"
                    save_rules(rules)
                    print(f"\n  {C.BGRN}[+]{C.RST} Rule {target_id} -> {r['action']}")
                    found = True
                    break
            if not found:
                print(f"\n  {C.BRED}[-]{C.RST} Not found")
            time.sleep(1.5)

        elif choice == 'A':
            print(f"\n  {C.BLD}--- Add New Rule ---{C.RST}")
            new_id = input("  Rule ID (e.g., R0200): ").strip().upper()
            if not new_id:
                print(f"  {C.BRED}[!]{C.RST} Rule ID is required")
                time.sleep(1.5)
                continue
            if any(r.get("rule_id", "").upper() == new_id for r in rule_list):
                print(f"  {C.BRED}[!]{C.RST} Rule {new_id} already exists")
                time.sleep(1.5)
                continue
            new_name = input("  Attack Name: ").strip()
            new_regex = input("  Regex Pattern: ").strip()
            new_layer = input("  Layer [NETWORK]: ").strip().upper() or "NETWORK"
            action_input = input("  Action (1=Alert, 2=Block, 3=Drop) [1]: ").strip()
            new_action = {"2": "Block", "3": "Drop"}.get(action_input, "Alert")
            ports_input = input("  Target Ports (comma-sep) [*]: ").strip()
            target_ports = []
            if ports_input and ports_input != "*":
                try: target_ports = [int(p.strip()) for p in ports_input.split(",") if p.strip()]
                except ValueError: pass
            proto_input = input("  Protocols (comma-sep) [*]: ").strip().upper()
            target_protocols = [p.strip() for p in proto_input.split(",") if p.strip()] if proto_input and proto_input != "*" else []
            new_fast_pattern = "CUSTOM"
            if new_regex and len(new_regex) >= 3:
                fp = ""
                for ch in new_regex:
                    if ch.isalnum():
                        fp += ch
                        if len(fp) >= 4: break
                if len(fp) >= 3: new_fast_pattern = fp
            new_rule = {
                "rule_id": new_id, "name": new_name, "category": "Custom Rule",
                "layer": new_layer, "fast_pattern": new_fast_pattern,
                "match_pattern": new_fast_pattern, "regex_pattern": new_regex,
                "severity": "High", "action": new_action,
            }
            if target_ports: new_rule["target_ports"] = target_ports
            if target_protocols: new_rule["target_protocols"] = target_protocols
            rules.setdefault("nids_rules", []).append(new_rule)
            save_rules(rules)
            print(f"\n  {C.BGRN}[+]{C.RST} Rule {new_id} created!")
            time.sleep(1.5)

        elif choice == 'D':
            target_id = input("  Rule ID to delete: ").strip().upper()
            initial = len(rule_list)
            rules["nids_rules"] = [r for r in rule_list if r.get("rule_id", "").upper() != target_id]
            if len(rules["nids_rules"]) < initial:
                save_rules(rules)
                print(f"\n  {C.BGRN}[+]{C.RST} Deleted!")
            else:
                print(f"\n  {C.BRED}[-]{C.RST} Not found")
            time.sleep(1.5)

        elif choice == 'H':
            try:
                os.utime(RULES_FILE, None)
                brain_sub = next((s for s in SUBSYSTEMS if s["name"] == "BRAIN"), None)
                brain_running, _ = check_subsystem(brain_sub) if brain_sub else (False, None)
                if brain_running:
                    print(f'\n  {C.BGRN}[+]{C.RST} Rules.json touched -- Brain will auto-reload')
                else:
                    print(f'\n  {C.YEL}[!]{C.RST} Rules.json touched, but Brain is NOT running -- reload on next start')
            except Exception as e:
                print(f"\n  {C.BRED}[-]{C.RST} Failed: {e}")
            time.sleep(1.5)

        elif choice == 'B':
            break


# =====================================================================
# 3. LOG MANAGEMENT
# =====================================================================

def menu_logs():
    """Log management -- Reset/Tail/View (single location, no overlap with daemon)."""
    while True:
        clear_screen()
        show_header()
        print(f"\n  {C.BLD}LOG MANAGEMENT{C.RST}")
        print(f"  {'─' * 50}")

        if os.path.exists(LOG_FILE):
            size = os.path.getsize(LOG_FILE)
            try:
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                count = len(lines)
            except Exception:
                count = "?"
            print(f"  Current: {count} entries, {size/1024:.1f} KB")
        else:
            print(f"  Log file not found (will create new)")

        print(f"""
  {C.BGRN}1{C.RST}  [RESET]     Clear logs (with backup)
  {C.BGRN}2{C.RST}  [TAIL]      Tail logs in real-time
  {C.BGRN}3{C.RST}  [VIEW]      View last 20 entries
  {C.YEL}0{C.RST}  [BACK]
""")
        choice = input(f"  {C.BLD}Select (0-3): {C.RST}").strip()

        if choice == '1':
            os.makedirs(os.path.join(PROJECT_ROOT, "logs"), exist_ok=True)
            if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup = os.path.join(PROJECT_ROOT, "logs", f"anomalous_{ts}.json")
                shutil.copy2(LOG_FILE, backup)
                print(f"\n  {C.BGRN}[+]{C.RST} Backup saved: {backup}")
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                pass
            print(f"  {C.BGRN}[+]{C.RST} Logs cleared.")
            input_pause()

        elif choice == '2':
            _tail_logs()

        elif choice == '3':
            _view_last_logs()

        elif choice == '0':
            break


def _tail_logs():
    print(f"\n  {C.CYN}[TAIL]{C.RST} Tailing {LOG_FILE} (Ctrl+C to exit)\n")
    if not os.path.exists(LOG_FILE):
        print(f"  {C.YEL}[!]{C.RST} Log file not found")
        input_pause()
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
                        color = C.BRED if policy in ("BLOCK", "DROP") else C.BYEL
                        print(f"  {color}[{ts}] {source} | {attack} | {policy}{C.RST}")
                    except json.JSONDecodeError:
                        print(f"  {C.DIM}{line.strip()}{C.RST}")
                else:
                    time.sleep(0.5)
    except KeyboardInterrupt:
        print(f"\n  {C.YEL}Stopped tailing.{C.RST}")


def _view_last_logs():
    if not os.path.exists(LOG_FILE):
        print(f"\n  {C.YEL}[!]{C.RST} No log file")
        input_pause()
        return
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        print(f"\n  {C.BLD}Last 20 entries:{C.RST}")
        for line in lines[-20:]:
            try:
                entry = json.loads(line.strip())
                ts = entry.get("timestamp", "?")
                attack = entry.get("attack_type", "?")
                policy = entry.get("policy", "?").upper()
                color = C.BRED if policy in ("BLOCK", "DROP") else C.DIM
                print(f"  {color}[{ts}] {attack} | {policy}{C.RST}")
            except json.JSONDecodeError:
                print(f"  {C.DIM}{line.strip()}{C.RST}")
    except Exception as e:
        print(f"  {C.BRED}[-]{C.RST} Error: {e}")
    input_pause()


# =====================================================================
# 4. THREAT GRAPH
# =====================================================================

def menu_threat_graph():
    clear_screen()
    show_header()
    if not AEGIS_GRAPH_AVAILABLE:
        print(f'\n  {C.BRED}[-]{C.RST} Threat graph unavailable -- pip install networkx pyvis')
        input_pause()
        return
    print(f"\n  {C.CYN}[GRAPH]{C.RST} Generating Threat Analysis Graph...")
    try:
        aegis_graph.generate_threat_graph()
        html_path = os.path.abspath(GRAPH_HTML_FILE)
        if os.path.exists(html_path):
            print(f"  {C.BGRN}[+]{C.RST} Graph generated!")
            import webbrowser
            webbrowser.open(f"file:///{html_path}")
        else:
            print(f"  {C.BRED}[-]{C.RST} File not found: {html_path}")
    except Exception as e:
        print(f"  {C.BRED}[ERROR]{C.RST} {e}")
    input_pause()


# =====================================================================
# 5. HEALTH & BRIDGE STATUS  (consolidated — no duplicate dashboard)
# =====================================================================

def menu_health():
    """System Health + Bridge Status -- single consolidated view."""
    while True:
        clear_screen()
        show_header()
        print(f"""
  {C.BLD}HEALTH & BRIDGE{C.RST}
  {'─' * 50}
  {C.BGRN}1{C.RST}  System Health     CPU, Memory, Network, Disk
  {C.BGRN}2{C.RST}  Bridge Status     IPC, DEFCON, round-trip test
  {C.BGRN}3{C.RST}  IPC Throughput    Measure msg/sec
  {C.YEL}0{C.RST}  Back
""")
        choice = input(f"  {C.BLD}Select (0-3): {C.RST}").strip()

        if choice == '1':
            _show_health()
        elif choice == '2':
            _show_bridge_status()
        elif choice == '3':
            _measure_ipc_throughput()
        elif choice == '0':
            break


def _show_health():
    """Health snapshot + real-time dashboard (merged -- no separate dashboard sub-menu)."""
    print(f"\n  {C.BLD}SYSTEM HEALTH{C.RST}")
    print(f"  {'═' * 55}")

    if not PSUTIL_AVAILABLE:
        print(f'  {C.YEL}[!]{C.RST} psutil not available -- pip install psutil')
        input_pause()
        return

    cpu = psutil.cpu_percent(interval=0.5)
    cpu_bar = draw_bar(cpu, 100, 20)
    cpu_color = C.BRED if cpu > 80 else C.BYEL if cpu > 50 else C.BGRN
    print(f"  CPU       : [{cpu_color}{cpu_bar}{C.RST}] {cpu:.1f}%")

    mem = psutil.virtual_memory()
    mem_bar = draw_bar(mem.percent, 100, 20)
    mem_color = C.BRED if mem.percent > 80 else C.BYEL if mem.percent > 50 else C.BGRN
    print(f"  Memory    : [{mem_color}{mem_bar}{C.RST}] {mem.percent:.1f}% ({mem.used/1024**3:.1f}/{mem.total/1024**3:.1f} GB)")

    try:
        disk_path = os.path.splitdrive(PROJECT_ROOT)[0] + '\\' if os.name == 'nt' else '/'
        disk = psutil.disk_usage(disk_path)
        disk_bar = draw_bar(disk.percent, 100, 20)
        disk_color = C.BRED if disk.percent > 80 else C.BYEL if disk.percent > 50 else C.BGRN
        print(f"  Disk      : [{disk_color}{disk_bar}{C.RST}] {disk.percent:.1f}%")
    except Exception:
        print(f"  Disk      : unavailable")

    try:
        net = psutil.net_io_counters()
        print(f"\n  {C.BLD}Network:{C.RST}  ^{net.bytes_sent/1024**2:.1f}MB  v{net.bytes_recv/1024**2:.1f}MB")
        if hasattr(net, 'errin'):
            print(f"  Errors/Drops: {net.errin}/{net.errout} err, {net.dropin}/{net.dropout} drop")
    except Exception:
        pass

    # Show subsystem status inline (single source of truth)
    print(f"\n  {C.BLD}Subsystem Health:{C.RST}")
    for sub in SUBSYSTEMS:
        running, pid = check_subsystem(sub)
        if running and pid and PSUTIL_AVAILABLE:
            try:
                proc = psutil.Process(int(pid))
                p_cpu = proc.cpu_percent(interval=0.1)
                p_mem = proc.memory_info().rss / 1024 / 1024
                print(f"  {sub['name']:<10} {C.BGRN}OK{C.RST}  PID={pid:<6} CPU={p_cpu:.1f}%  MEM={p_mem:.1f}MB")
            except Exception:
                print(f"  {sub['name']:<10} {C.YEL}?{C.RST}  PID={pid}")
        else:
            print(f"  {sub['name']:<10} {C.BRED}DOWN{C.RST}")

    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
            blocks = sum(1 for l in lines if '"policy": "Block"' in l or '"policy": "Drop"' in l)
            print(f"\n  {C.BLD}Threat Log:{C.RST} {len(lines)} alerts, {blocks} blocks/drops")
        except Exception:
            pass

    # Offer real-time dashboard
    print(f"\n  {C.DIM}Press 'D' for real-time dashboard, or Enter to go back{C.RST}")
    key = input(f"  {C.BLD}Choice: {C.RST}").strip().upper()
    if key == 'D':
        _run_realtime_dashboard()
    else:
        return


def _run_realtime_dashboard():
    """Real-time dashboard -- accessed only from Health menu 'D' key."""
    print(f"\n  {C.CYN}[DASHBOARD]{C.RST} Press Ctrl+C to exit\n")
    if PSUTIL_AVAILABLE:
        psutil.cpu_percent(interval=None)
    try:
        while True:
            now = datetime.now().strftime("%H:%M:%S")
            defcon_level, defcon_label = get_defcon()
            if defcon_level:
                dc = DEFCON_COLORS.get(defcon_level, C.RST)
                defcon_str = f"{dc}DEFCON {defcon_level} {defcon_label}{C.RST}"
            else:
                defcon_str = f"{C.DIM}DEFCON N/A{C.RST}"

            statuses = get_all_status()
            running = sum(1 for _, _, r, _ in statuses if r)

            cpu = psutil.cpu_percent(interval=0) if PSUTIL_AVAILABLE else 0
            mem = psutil.virtual_memory() if PSUTIL_AVAILABLE else None
            mem_pct = mem.percent if mem else 0

            clear_screen()
            print(f"  {'═' * 58}")
            print(f'  {C.BLD}AEGIS NIDS -- REAL-TIME DASHBOARD{C.RST}   {C.DIM}{now}{C.RST}')
            print(f"  {'═' * 58}")
            print(f"  {defcon_str}")
            print(f"  Subsystems: {C.BLD}{running}/{len(SUBSYSTEMS)}{C.RST} running\n")

            for name, lang, is_running, pid in statuses:
                icon = f"{C.BGRN}●{C.RST}" if is_running else f"{C.BRED}○{C.RST}"
                st = f"{C.BGRN}RUN{C.RST}" if is_running else f"{C.BRED}STOP{C.RST}"
                print(f"  {icon} {name:<8} [{lang:<6}] {st}  PID:{pid or '-':<6}")

            print()
            cpu_bar = draw_bar(cpu, 100, 20)
            cpu_color = C.BRED if cpu > 80 else C.BYEL if cpu > 50 else C.BGRN
            print(f"  CPU  [{cpu_color}{cpu_bar}{C.RST}] {cpu:.1f}%")
            if mem:
                mem_bar = draw_bar(mem_pct, 100, 20)
                mem_color = C.BRED if mem_pct > 80 else C.BYEL if mem_pct > 50 else C.BGRN
                print(f"  MEM  [{mem_color}{mem_bar}{C.RST}] {mem_pct:.1f}%")

            if PSUTIL_AVAILABLE:
                try:
                    net = psutil.net_io_counters()
                    print(f"\n  {C.DIM}NET  ^{net.bytes_sent/1024**2:.1f}MB  v{net.bytes_recv/1024**2:.1f}MB{C.RST}")
                except Exception:
                    pass

            print(f"\n  {C.DIM}Ctrl+C to exit{C.RST}")
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n  {C.YEL}Dashboard stopped.{C.RST}")
        time.sleep(0.5)


def _show_bridge_status():
    print(f'\n  {C.BLD}BRIDGE -- IPC STATUS{C.RST}')
    print(f"  {'═' * 55}")

    if not BRIDGE_AVAILABLE:
        print(f"  {C.BRED}[!]{C.RST} aegis_bridge_ctypes not available")
        input_pause()
        return

    rc = bridge.bridge_init()
    if rc != 0:
        print(f"  {C.BRED}[!]{C.RST} Bridge init failed (rc={rc})")
        input_pause()
        return

    try:
        defcon = bridge.get_defcon_level()
        label = bridge.get_defcon_label()
        desc = bridge.get_defcon_description()
        color = DEFCON_COLORS.get(defcon, C.RST)
        print(f'  DEFCON    : {color}{defcon} -- {label}{C.RST}')
        print(f"  Scale     : {color}{DEFCON_SCALE.get(defcon, '')}{C.RST}")
        print(f"  Desc      : {desc}")

        event_count = bridge.get_event_count()
        dropped = bridge.get_dropped_count()
        print(f"  Events    : {C.BBLU}{event_count}{C.RST}")
        print(f"  Dropped   : {C.BRED if dropped > 0 else C.BGRN}{dropped}{C.RST}")

        print(f"\n  {C.BLD}IPC Round-Trip:{C.RST}")
        rc = bridge.push_event(
            event_type=0, source_ip=0, dest_ip=0,
            source_port=0, dest_port=0, protocol=6,
            tier_result=1, rule_id=0, severity=0,
        )
        if rc == 0:
            print(f"  Push      : {C.BGRN}OK{C.RST}")
            event = bridge.pop_event()
            if event:
                print(f"  Pop       : {C.BGRN}OK{C.RST} (rule_id={event.rule_id})")
            else:
                print(f"  Pop       : {C.BRED}FAILED{C.RST}")
        else:
            print(f"  Push      : {C.BRED}FAILED{C.RST} (rc={rc})")

    finally:
        bridge.bridge_shutdown()

    print(f"  {'═' * 55}")
    input_pause()


def _measure_ipc_throughput():
    if not BRIDGE_AVAILABLE:
        print(f"\n  {C.BRED}[-]{C.RST} Bridge not available")
        input_pause()
        return
    rc = bridge.bridge_init()
    if rc != 0:
        print(f"\n  {C.BRED}[-]{C.RST} Bridge init failed")
        input_pause()
        return

    print(f"\n  {C.CYN}[IPC]{C.RST} Measuring throughput (3s)...")
    try:
        count = 0
        start = time.perf_counter()
        end_time = start + 3.0
        while time.perf_counter() < end_time:
            rc = bridge.push_event(
                event_type=0, source_ip=0, dest_ip=0,
                source_port=0, dest_port=0, protocol=6,
                tier_result=1, rule_id=0, severity=0,
            )
            if rc == 0:
                count += 1
            else:
                break
        elapsed = time.perf_counter() - start
        rate = count / elapsed if elapsed > 0 else 0
        print(f"  Sent      : {C.BBLU}{count:,}{C.RST} messages")
        print(f"  Elapsed   : {elapsed:.3f}s")
        print(f"  Throughput: {C.BGRN}{rate:,.0f} msg/sec{C.RST}")
    finally:
        bridge.bridge_shutdown()
    input_pause()


# =====================================================================
# 6. TEST SUITE  (fixed: single _avail marker per test)
# =====================================================================

def _avail(script_name):
    """Return availability marker for test scripts."""
    path = os.path.join(SCRIPT_DIR, script_name)
    return "" if os.path.exists(path) else f" {C.DIM}[N/A]{C.RST}"


def menu_tests():
    while True:
        clear_screen()
        show_header()
        print(f"""
  {C.BLD}TEST SUITE{C.RST}
  {'─' * 55}
  {C.BGRN}1{C.RST}  IPC Stress Test     throughput + multi-channel{_avail("aegis_ipc_stress_test.py")}
  {C.BGRN}2{C.RST}  Npcap Capture Test  packet capture + IPC{_avail("aegis_npcap_test.py")}
  {C.BGRN}3{C.RST}  Full Verification   12 tests comprehensive{_avail("aegis_verify_all.py")}
  {C.BGRN}4{C.RST}  Alert Integration   Brain->DEFCON->Mouth pipeline{_avail("aegis_alert_integration.py")}
  {C.BGRN}5{C.RST}  Attack Simulation   5-phase attack (Recon->Exfil)
  {C.BGRN}6{C.RST}  E2E Test            test_e2e.py
  {C.YEL}0{C.RST}  Back
""")
        choice = input(f"  {C.BLD}Select (0-6): {C.RST}").strip()

        if choice == '1':
            _run_test_script("aegis_ipc_stress_test.py", "IPC Stress Test")
        elif choice == '2':
            _run_test_script("aegis_npcap_test.py", "Npcap Capture Test")
        elif choice == '3':
            _run_test_script("aegis_verify_all.py", "Full Verification")
        elif choice == '4':
            _run_test_script("aegis_alert_integration.py", "Alert Integration")
        elif choice == '5':
            _run_attack_simulation()
        elif choice == '6':
            _run_test_script(os.path.join(PROJECT_ROOT, "tests", "test_e2e.py"), "E2E Test")
        elif choice == '0':
            break


def _run_test_script(script_name, display_name):
    if os.path.isabs(script_name):
        script_path = script_name
    else:
        script_path = os.path.join(SCRIPT_DIR, script_name)
    if not os.path.exists(script_path):
        print(f"\n  {C.BRED}[-]{C.RST} {script_name} not found")
        input_pause()
        return
    print(f"\n  {C.CYN}[TEST]{C.RST} Running {display_name}...")
    print(f"  {'─' * 50}")
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=False, text=True, timeout=120, cwd=SCRIPT_DIR,
        )
        if result.returncode == 0:
            print(f"\n  {C.BGRN}[PASS]{C.RST} {display_name} succeeded")
        else:
            print(f"\n  {C.BRED}[FAIL]{C.RST} exit={result.returncode}")
    except FileNotFoundError:
        print(f"  {C.BRED}[-]{C.RST} Not found: {script_path}")
    except subprocess.TimeoutExpired:
        print(f"  {C.BRED}[-]{C.RST} Timed out (120s)")
    except Exception as e:
        print(f"  {C.BRED}[-]{C.RST} Error: {e}")
    input_pause()


def _run_attack_simulation():
    print(f"\n  {C.BRED}{C.BLD}[ATTACK SIM]{C.RST} 5-Phase Attack Simulation")
    print(f"  {'─' * 50}")

    script_path = os.path.join(SCRIPT_DIR, "aegis_alert_integration.py")
    if os.path.exists(script_path):
        try:
            result = subprocess.run(
                [sys.executable, script_path, "--inject"],
                capture_output=False, text=True, timeout=60, cwd=SCRIPT_DIR,
            )
        except Exception as e:
            print(f"  {C.BRED}[-]{C.RST} Error: {e}")
    elif BRIDGE_AVAILABLE:
        rc = bridge.bridge_init()
        if rc == 0:
            try:
                phases = [
                    ("Phase 1: RECONNAISSANCE", 3),
                    ("Phase 2: BRUTE FORCE", 8),
                    ("Phase 3: EXPLOITATION", 15),
                    ("Phase 4: LATERAL MOVE", 10),
                    ("Phase 5: EXFILTRATION", 5),
                ]
                for phase_name, count in phases:
                    print(f"\n  {C.BRED}{C.BLD}{phase_name}{C.RST}")
                    for i in range(count):
                        rc = bridge.push_event(
                            event_type=1, source_ip=0xC0A80101 + i,
                            dest_ip=0xC0A80164, source_port=49152 + i * 100,
                            dest_port=22, protocol=6, tier_result=2,
                            rule_id=100 + i, severity=3,
                        )
                        if rc == 0:
                            print(f"    {C.BRED}>{C.RST} Alert {i+1}/{count} via IPC")
                            time.sleep(0.15)
                print(f"\n  {C.BGRN}[DONE]{C.RST} Attack simulation complete")
            finally:
                bridge.bridge_shutdown()
        else:
            print(f"  {C.BRED}[-]{C.RST} Bridge init failed")
    else:
        print(f"  {C.BRED}[-]{C.RST} No alert integration or Bridge available")
    input_pause()


# =====================================================================
# 7. DAEMON  (slim -- only unique commands not covered elsewhere)
# =====================================================================

def menu_daemon():
    """Daemon commands -- slim menu: only commands NOT available elsewhere.

    Removed: start/stop (use main START/STOP), status (use main STATUS),
             health (use HEALTH), logs (use LOGS), watchdog (use main WD toggle).
    Kept: restart, rules hot-reload via daemon, daemon-specific status.
    """
    while True:
        clear_screen()
        show_header()
        print(f"""
  {C.BLD}DAEMON COMMANDS{C.RST} (via aegis_daemon.py)
  {'─' * 55}
  {C.BLD}Note:{C.RST} START/STOP/STATUS/WATCHDOG/LOGS are in main menu
  {'─' * 55}
  {C.BGRN}1{C.RST}  restart     รีสตาร์ท daemon
  {C.BGRN}2{C.RST}  daemon-status  สถานะ daemon (เฉพาะ daemon process)
  {C.BGRN}3{C.RST}  rules       Hot-reload rules (via daemon)
  {C.YEL}0{C.RST}  Back
""")
        choice = input(f"  {C.BLD}Select (0-3): {C.RST}").strip()

        daemon_cmds = {'1': 'restart', '2': 'status', '3': 'rules'}

        if choice in daemon_cmds:
            cmd = daemon_cmds[choice]
            daemon_script = os.path.join(SCRIPT_DIR, "aegis_daemon.py")
            if not os.path.exists(daemon_script):
                print(f"\n  {C.BRED}[-]{C.RST} aegis_daemon.py not found")
                input_pause()
                continue

            print(f"\n  {C.CYN}[DAEMON]{C.RST} python aegis_daemon.py {cmd}")
            print(f"  {'─' * 50}")
            try:
                result = subprocess.run(
                    [sys.executable, daemon_script, cmd],
                    capture_output=False, text=True, timeout=30,
                    cwd=SCRIPT_DIR,
                )
            except FileNotFoundError:
                print(f"  {C.BRED}[-]{C.RST} aegis_daemon.py not found")
            except subprocess.TimeoutExpired:
                print(f"  {C.BRED}[-]{C.RST} Timed out")
            except Exception as e:
                print(f"  {C.BRED}[-]{C.RST} Error: {e}")
            input_pause()

        elif choice == '0':
            break


# =====================================================================
# MAIN MENU  (flat, clear grouping, no overlapping)
# =====================================================================

def main_menu():
    while True:
        clear_screen()
        show_header()

        statuses = get_all_status()
        running = sum(1 for _, _, r, _ in statuses if r)
        total = len(SUBSYSTEMS)

        print(f"""
  {C.BLD}{C.CYN}SYSTEM{C.RST}
  {'─' * 50}
  {C.BGRN}1{C.RST}  [START]     เปิดระบบทั้งหมด (run_aegis.bat)
  {C.BGRN}2{C.RST}  [STOP]      หยุดระบบทั้งหมด (stop_aegis.bat)
  {C.BGRN}3{C.RST}  [RESTART]   รีสตาร์ทระบบทั้งหมด
  {C.BGRN}4{C.RST}  [STATUS]    สถานะ subsystem ทุกตัว
  {C.BGRN}5{C.RST}  [WATCHDOG]  เปิด/ปิด Watchdog (auto-restart)

  {C.BLD}{C.YEL}CONTROL{C.RST}
  {'─' * 50}
  {C.BGRN}6{C.RST}  [MOUTH]     Mouth Control (Start/Stop/Rebuild)
  {C.BGRN}7{C.RST}  [RULES]     จัดการ Detection Rules
  {C.BGRN}8{C.RST}  [LOGS]      จัดการ Logs

  {C.BLD}{C.GRN}ANALYSIS{C.RST}
  {'─' * 50}
  {C.BGRN}9{C.RST}  [HEALTH]    สุขภาพระบบ + Bridge IPC
  {C.BGRN}A{C.RST}  [GRAPH]     Threat Map
  {C.BGRN}B{C.RST}  [TEST]      E2E / Test Suite
  {C.BGRN}C{C.RST}  [DAEMON]    Daemon Commands (เฉพาะ)

  {C.BLD}0{C.RST}  [EXIT]      ปิด Console
""")

        # Single status indicator (no duplicate)
        if running == total:
            print(f"  {C.BGRN}● AEGIS FULLY OPERATIONAL{C.RST}")
        elif running > 0:
            print(f"  {C.BYEL}◐ PARTIALLY RUNNING ({running}/{total}){C.RST}")
        else:
            print(f"  {C.BRED}○ SYSTEM STOPPED{C.RST}")

        choice = input(f"\n  {C.BLD}Select (0-9/A-C): {C.RST}").strip().upper()

        # ── SYSTEM ──
        if choice == '1':
            # START — direct, no nested menu
            print(f"\n  {C.CYN}[START]{C.RST} Launching AEGIS NIDS...")
            bat = os.path.join(SCRIPT_DIR, "run_aegis.bat")
            if os.path.exists(bat):
                subprocess.Popen(["cmd", "/c", bat, "--no-dashboard"],
                                  creationflags=getattr(subprocess, 'CREATE_NEW_CONSOLE', 0))
                print(f"  {C.BGRN}OK{C.RST} run_aegis.bat launched in new console")
            else:
                launched, skipped = _launch_all_subsystems()
                print(f"  {C.BGRN}OK{C.RST} Launched {launched} subsystem(s), skipped {skipped}")
            input_pause()

        elif choice == '2':
            # STOP — direct, no nested menu
            print(f"\n  {C.CYN}[STOP]{C.RST} Stopping AEGIS NIDS...")
            _kill_all_subsystems()
            print(f"  {C.BGRN}OK{C.RST} System stopped.")
            input_pause()

        elif choice == '3':
            # RESTART — direct
            print(f"\n  {C.CYN}[RESTART]{C.RST} Restarting...")
            _kill_all_subsystems()
            time.sleep(2)
            bat = os.path.join(SCRIPT_DIR, "run_aegis.bat")
            if os.path.exists(bat):
                subprocess.Popen(["cmd", "/c", bat, "--no-dashboard"],
                                  creationflags=getattr(subprocess, 'CREATE_NEW_CONSOLE', 0))
                print(f"  {C.BGRN}OK{C.RST} run_aegis.bat launched")
            else:
                launched, skipped = _launch_all_subsystems()
                print(f"  {C.BGRN}OK{C.RST} Launched {launched} subsystem(s), skipped {skipped}")
            input_pause()

        elif choice == '4':
            # STATUS — inline, single source of truth (no separate menu_status function)
            show_subsystem_detail()
            defcon_level, defcon_label = get_defcon()
            if defcon_level:
                dc = DEFCON_COLORS.get(defcon_level, C.RST)
                print(f'\n  DEFCON: {dc}{defcon_level} -- {defcon_label}{C.RST}')
            input_pause()

        elif choice == '5':
            # WATCHDOG — direct toggle (single implementation)
            toggle_watchdog()

        # ── CONTROL ──
        elif choice == '6':
            menu_mouth()
        elif choice == '7':
            menu_rules()
        elif choice == '8':
            menu_logs()

        # ── ANALYSIS ──
        elif choice == '9':
            menu_health()
        elif choice == 'A':
            menu_threat_graph()
        elif choice == 'B':
            menu_tests()
        elif choice == 'C':
            menu_daemon()

        # ── EXIT ──
        elif choice == '0':
            answer = input(f"\n  {C.BYEL}Stop all subsystems before exit? (y/N): {C.RST}").strip().lower()
            if answer == 'y':
                _kill_all_subsystems()
                print(f"  {C.BGRN}[OK]{C.RST} All subsystems stopped.")
            print(f"\n  {C.DIM}Shutting down Command Center...{C.RST}")
            break
        else:
            time.sleep(0.5)


# =====================================================================
# ENTRY POINT
# =====================================================================

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{C.YEL}[!]{C.RST} Command Center stopped.")
