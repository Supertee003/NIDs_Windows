#!/usr/bin/env python
"""
AEGIS NIDS — Daemon Manager (v3 — Standalone CLI)
===================================================
Background service controller — NO interactive menus, NO colors.
Designed for scripts, Task Scheduler, NSSM, and headless operation.

Uses aegis_common for all shared logic.

Commands:
  start       Start all subsystems as background processes
  stop        Stop all subsystems gracefully
  restart     Restart (stop + start)
  status      Show running status (machine-readable friendly)
  health      System health check (CPU, memory, network)
  rules       Hot-reload Rules.json (touch mtime)
  logs        Tail logs/anomalous.json in real-time
  watchdog    Monitor + auto-restart crashed subsystems
  build       Build all binaries (CMake + Cargo + Mouth)
  mouth       Build/rebuild Mouth binary only
  install     Install as Windows Service (NSSM guide)
  uninstall   Uninstall Windows Service

Usage:
  python aegis_daemon.py start          # start everything
  python aegis_daemon.py status         # check status
  python aegis_daemon.py health         # health check
  python aegis_daemon.py watchdog       # auto-restart on crash
  python aegis_daemon.py stop           # stop everything
  python aegis_daemon.py build          # build all binaries
  python aegis_daemon.py logs           # tail threat log

Design:
  - Pure CLI output (no ANSI colors, no menus, no input prompts)
  - All output is log-style: [TIMESTAMP] [LEVEL] message
  - Suitable for redirect to file, pipe to grep, or systemd/journal
  - Calls aegis_common for process/build logic
  - PID files track all subsystems
  - Smart build: skip if binaries are up-to-date
"""
import os
import sys
import json
import time
import subprocess
from datetime import datetime

# Import shared library
try:
    import aegis_common as common
except ImportError:
    print("[FATAL] Cannot import aegis_common.py — must be in same directory")
    sys.exit(1)


# =====================================================================
# LOGGING (plain text, no colors — for files/pipes/services)
# =====================================================================
def log(msg, level="INFO"):
    line = common.daemon_log(msg, level)
    print(line)


# =====================================================================
# BUILD COMMAND
# =====================================================================
def cmd_build(args):
    """Build all binaries: C++ Bridge (cmake) + Rust FFI (cargo) + Mouth (rustc)."""
    log("=" * 60)
    log("Building AEGIS NIDS binaries...")
    log("=" * 60)
    errors = 0

    # Build C++ IPC Bridge
    bridge_sub = next((s for s in common.SUBSYSTEMS if s["key"] == "bridge"), None)
    if bridge_sub and common.subsystem_needs_rebuild(bridge_sub):
        log("Building C++ IPC Bridge (cmake) — source changed...")
        result = subprocess.run(
            ["cmake", "-B", "build", "-DCMAKE_BUILD_TYPE=Release"],
            cwd=str(common.BASE_DIR), capture_output=True, text=True,
        )
        if result.returncode != 0:
            log(f"CMake configure FAILED: {result.stderr.strip()[:200]}", "ERROR")
            errors += 1
        else:
            result = subprocess.run(
                ["cmake", "--build", "build", "--config", "Release"],
                cwd=str(common.BASE_DIR), capture_output=True, text=True,
            )
            if result.returncode != 0:
                log(f"CMake build FAILED: {result.stderr.strip()[:200]}", "ERROR")
                errors += 1
            else:
                log("C++ IPC Bridge build OK")
    else:
        log("C++ IPC Bridge — up-to-date, skip")

    # Build Rust FFI
    mouth_sub = next((s for s in common.SUBSYSTEMS if s["key"] == "mouth"), None)
    if mouth_sub and common.subsystem_needs_rebuild(mouth_sub):
        log("Building Rust FFI (cargo --release) — source changed...")
        result = subprocess.run(
            ["cargo", "build", "--release", "--manifest-path", "Cargo.toml"],
            cwd=str(common.BASE_DIR), capture_output=True, text=True,
        )
        if result.returncode != 0:
            log(f"Rust FFI build FAILED: {result.stderr.strip()[:200]}", "ERROR")
            errors += 1
        else:
            log("Rust FFI build OK")
    else:
        log("Rust FFI — up-to-date, skip")

    # Build Mouth standalone binary
    if common.needs_rebuild(common.MOUTH_SRC, common.MOUTH_EXE) or not (common.BASE_DIR / common.MOUTH_EXE).exists():
        log("Building Mouth binary (windows_sec_monitor.exe)...")
        ok = common.build_mouth_exe(verbose=False)
        if ok:
            log("Mouth binary build OK")
        else:
            log("Mouth binary build FAILED", "ERROR")
            errors += 1
    else:
        log("Mouth binary — up-to-date, skip")

    if errors == 0:
        log("All builds completed successfully")
    else:
        log(f"Build completed with {errors} error(s)", "ERROR")
    return errors == 0


# =====================================================================
# START COMMAND
# =====================================================================
def cmd_start(args):
    """Start all NIDS subsystems as background processes."""
    common.ensure_dirs()

    # Clear log file
    common.LOG_FILE.write_text("", encoding="utf-8")

    log("=" * 60)
    log("Starting AEGIS NIDS daemon — all subsystems")
    log("=" * 60)

    # Build first (smart — skips up-to-date)
    cmd_build([])

    # Start each subsystem
    started = 0
    for sub in common.SUBSYSTEMS:
        name = sub["key"]
        pid = common.read_pid(name)
        if pid and common.is_pid_running(pid):
            log(f"  [{name}] already running (PID {pid}) — skip")
            started += 1
            continue

        log(f"  [{name}] starting: {sub['start_cmd']}")
        try:
            kwargs = {
                "cwd": str(common.BASE_DIR),
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
            }
            if os.name == 'nt':
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

            proc = subprocess.Popen(sub["start_cmd"], shell=True, **kwargs)
            common.write_pid(name, proc.pid)
            log(f"  [{name}] started (PID {proc.pid})")
            started += 1
            time.sleep(1)
        except Exception as e:
            log(f"  [{name}] FAILED: {e}", "ERROR")

    log(f"Started {started}/{len(common.SUBSYSTEMS)} subsystems.")
    log("Use 'aegis_daemon.py status' to check.")
    log("Use 'aegis_daemon.py watchdog' for auto-restart monitoring.")
    return True


# =====================================================================
# STOP COMMAND
# =====================================================================
def cmd_stop(args):
    """Stop all NIDS subsystems gracefully."""
    log("=" * 60)
    log("Stopping AEGIS NIDS daemon...")
    log("=" * 60)

    stopped = 0
    for sub in common.SUBSYSTEMS:
        name = sub["key"]
        pid = common.read_pid(name)
        if pid and common.is_pid_running(pid):
            log(f"  [{name}] stopping PID {pid}...")
            common.stop_pid(pid)
            stopped += 1
            common.clear_pid(name)
            continue

        # Fallback: find by pattern
        procs = common.find_processes_by_pattern(sub["stop_pattern"])
        for proc in procs:
            log(f"  [{name}] stopping PID {proc.pid} (pattern match)...")
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
                stopped += 1
            except Exception:
                pass
        common.clear_pid(name)

    log(f"Stopped {stopped} processes.")
    return True


# =====================================================================
# RESTART COMMAND
# =====================================================================
def cmd_restart(args):
    """Restart all subsystems."""
    cmd_stop(args)
    time.sleep(2)
    cmd_start(args)


# =====================================================================
# STATUS COMMAND
# =====================================================================
def cmd_status(args):
    """Show running status of all subsystems. Machine-readable format."""
    print(f"AEGIS NIDS — Daemon Status")
    print(f"{'SUBSYSTEM':<12} {'STATUS':<10} {'PID':<8} {'CPU':<8} {'MEM':<8} {'DESCRIPTION'}")
    print("-" * 80)

    running_count = 0
    for sub in common.SUBSYSTEMS:
        name = sub["key"]
        pid = common.read_pid(name)
        running = pid and common.is_pid_running(pid)
        status = "RUNNING" if running else "STOPPED"
        pid_str = str(pid) if pid else "-"

        if running:
            cpu, mem = common.get_process_cpu_mem(pid)
            cpu_str = f"{cpu:.1f}%" if cpu is not None else "-"
            mem_str = f"{mem:.1f}MB" if mem is not None else "-"
            running_count += 1
        else:
            cpu_str = "-"
            mem_str = "-"

        print(f"{name:<12} {status:<10} {pid_str:<8} {cpu_str:<8} {mem_str:<8} {sub['description']}")

    print(f"\n{running_count}/{len(common.SUBSYSTEMS)} subsystems running")

    # Log stats
    if common.LOG_FILE.exists():
        try:
            line_count = sum(1 for _ in open(common.LOG_FILE, encoding="utf-8"))
            size_kb = common.LOG_FILE.stat().st_size / 1024
            print(f"Log: {line_count} entries, {size_kb:.1f} KB")
        except Exception:
            pass

    return True


# =====================================================================
# HEALTH COMMAND
# =====================================================================
def cmd_health(args):
    """System health check — CPU, memory, disk, network, threats."""
    print("AEGIS NIDS — Health Check")
    print("=" * 60)

    # Process health
    print("\nProcesses:")
    for sub in common.SUBSYSTEMS:
        name = sub["key"]
        pid = common.read_pid(name)
        if pid and common.is_pid_running(pid):
            cpu, mem = common.get_process_cpu_mem(pid)
            cpu_str = f"CPU={cpu:.1f}%" if cpu is not None else ""
            mem_str = f"MEM={mem:.1f}MB" if mem is not None else ""
            print(f"  {name:<12} OK      PID={pid:<6} {cpu_str} {mem_str}")
        else:
            print(f"  {name:<12} DOWN")

    # System resources
    if common.PSUTIL_AVAILABLE:
        import psutil
        print("\nSystem:")
        print(f"  CPU    : {psutil.cpu_percent(interval=0.5):.1f}%")
        mem = psutil.virtual_memory()
        print(f"  Memory : {mem.percent:.1f}% ({mem.used / 1024**3:.1f} GB / {mem.total / 1024**3:.1f} GB)")
        disk_path = "C:\\" if os.name == 'nt' else "/"
        try:
            disk = psutil.disk_usage(disk_path)
            print(f"  Disk   : {disk.percent:.1f}% used")
        except Exception:
            pass

        try:
            net = psutil.net_io_counters()
            print(f"\nNetwork (since boot):")
            print(f"  Packets  : {net.packets_sent:,} sent / {net.packets_recv:,} recv")
            print(f"  Bytes    : {net.bytes_sent / 1024**2:.1f} MB sent / {net.bytes_recv / 1024**2:.1f} MB recv")
            if hasattr(net, 'errin'):
                print(f"  Errors   : {net.errin}/{net.errout}  Drops: {net.dropin}/{net.dropout}")
        except Exception:
            pass
    else:
        print("\n  (psutil not available — install for system stats)")

    # Threat log
    if common.LOG_FILE.exists():
        try:
            with open(common.LOG_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
            blocks = sum(1 for l in lines if '"Block"' in l or '"Drop"' in l)
            print(f"\nThreat Log: {len(lines)} alerts, {blocks} blocks/drops")
        except Exception:
            pass

    return True


# =====================================================================
# RULES COMMAND
# =====================================================================
def cmd_rules(args):
    """Hot-reload Rules.json (touch mtime → Brain auto-reloads)."""
    if not common.RULES_FILE.exists():
        log(f"Rules file not found: {common.RULES_FILE}", "ERROR")
        return False

    os.utime(common.RULES_FILE, None)
    log("Rules.json touched — Brain will auto-reload within 1s")
    log(f"File: {common.RULES_FILE} ({common.RULES_FILE.stat().st_size} bytes)")

    try:
        with open(common.RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        log(f"Total rules: {len(data.get('nids_rules', []))}")
    except Exception:
        pass
    return True


# =====================================================================
# LOGS COMMAND (tail -f)
# =====================================================================
def cmd_logs(args):
    """Tail logs/anomalous.json in real-time."""
    print(f"Tailing {common.LOG_FILE} (Ctrl+C to exit)...\n")
    if not common.LOG_FILE.exists():
        print("Log file does not exist — start the daemon first.")
        return

    try:
        with open(common.LOG_FILE, "r", encoding="utf-8") as f:
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
                        severity = entry.get("severity", "")
                        sev_str = f" [{severity}]" if severity else ""
                        marker = "!!" if policy in ("BLOCK", "DROP") else ">>"
                        print(f"[{marker}] [{ts}] {source} | {attack}{sev_str} | {policy}")
                    except json.JSONDecodeError:
                        print(line.strip())
                else:
                    time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopped tailing.")


# =====================================================================
# WATCHDOG COMMAND
# =====================================================================
def cmd_watchdog(args):
    """Monitor subsystems and auto-restart crashed ones."""
    common.ensure_dirs()
    log("=" * 60)
    log("AEGIS Watchdog started — monitoring subsystems")
    log("Press Ctrl+C to stop")
    log("=" * 60)

    check_interval = 5
    restart_times = {}  # name -> [timestamps]
    max_restarts_per_minute = 3

    try:
        while True:
            now = time.time()
            for sub in common.SUBSYSTEMS:
                name = sub["key"]
                pid = common.read_pid(name)

                if pid and common.is_pid_running(pid):
                    continue  # running fine

                # Crashed — check rate limit
                recent = restart_times.get(name, [])
                recent = [t for t in recent if now - t < 60]
                restart_times[name] = recent

                if len(recent) >= max_restarts_per_minute:
                    log(f"  [{name}] crash loop detected ({max_restarts_per_minute}/min) — waiting", "WARN")
                    continue

                log(f"  [{name}] CRASHED (PID {pid} gone) — restarting...", "WARN")
                common.clear_pid(name)

                try:
                    kwargs = {
                        "cwd": str(common.BASE_DIR),
                        "stdout": subprocess.DEVNULL,
                        "stderr": subprocess.DEVNULL,
                    }
                    if os.name == 'nt':
                        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

                    proc = subprocess.Popen(sub["start_cmd"], shell=True, **kwargs)
                    common.write_pid(name, proc.pid)
                    recent.append(now)
                    restart_times[name] = recent
                    log(f"  [{name}] restarted (new PID {proc.pid})")
                except Exception as e:
                    log(f"  [{name}] restart FAILED: {e}", "ERROR")

            time.sleep(check_interval)

    except KeyboardInterrupt:
        log("Watchdog stopped by user")


# =====================================================================
# MOUTH BUILD COMMAND
# =====================================================================
def cmd_mouth(args):
    """Build or rebuild Mouth binary only."""
    force = "--force" in args or "-f" in args
    log(f"Building Mouth binary {'(force)' if force else ''}...")
    ok = common.build_mouth_exe(verbose=False, force=force)
    if ok:
        exe_path = common.BASE_DIR / common.MOUTH_EXE
        if exe_path.exists():
            mtime = datetime.fromtimestamp(exe_path.stat().st_mtime)
            size_kb = exe_path.stat().st_size / 1024
            log(f"Mouth binary OK — {size_kb:.1f} KB, modified {mtime}")
        return True
    else:
        log("Mouth binary build FAILED", "ERROR")
        return False


# =====================================================================
# INSTALL / UNINSTALL (guide only)
# =====================================================================
def cmd_install(args):
    """Print NSSM installation guide."""
    print("Windows Service Installation (via NSSM):")
    print("  1. Download nssm from https://nssm.cc/download")
    print("  2. nssm install AegisNIDS python aegis_daemon.py start")
    print("  3. nssm set AegisNIDS AppDirectory " + str(common.BASE_DIR))
    print("  4. nssm set AegisNIDS DisplayName \"AEGIS NIDS Daemon\"")
    print("  5. nssm set AegisNIDS Start ServiceAutoStart")
    print("  6. nssm start AegisNIDS")
    print()
    print("Alternative: Use 'aegis_daemon.py watchdog' for auto-restart without service.")


def cmd_uninstall(args):
    """Print NSSM uninstall guide."""
    print("Windows Service Uninstall (via NSSM):")
    print("  nssm stop AegisNIDS")
    print("  nssm remove AegisNIDS confirm")


# =====================================================================
# HELP
# =====================================================================
def cmd_help(args):
    """Show help."""
    print(f"""
AEGIS NIDS — Daemon Manager v3 (Standalone CLI)
================================================

Usage: python aegis_daemon.py <command> [options]

Commands:
  start       Start all subsystems (background, no windows)
  stop        Stop all subsystems
  restart     Restart all subsystems
  status      Show status of all subsystems (PID, CPU, MEM)
  health      System health (CPU, memory, disk, network, threats)
  rules       Hot-reload Rules.json (Brain auto-reloads)
  logs        Tail threat log (Ctrl+C to exit)
  watchdog    Auto-restart crashed subsystems (Ctrl+C to exit)
  build       Build all binaries (cmake + cargo + rustc)
  mouth       Build Mouth binary only (--force to rebuild)
  install     Print Windows Service install guide
  uninstall   Print Windows Service uninstall guide
  help        Show this help

Options:
  --force, -f   Force rebuild (for 'mouth' command)

Examples:
  python aegis_daemon.py start
  python aegis_daemon.py status
  python aegis_daemon.py health
  python aegis_daemon.py watchdog
  python aegis_daemon.py mouth --force
  python aegis_daemon.py stop

Output:
  All output is plain text log format — suitable for:
  - Redirect to file:  python aegis_daemon.py start > daemon.log 2>&1
  - Pipe to grep:      python aegis_daemon.py status | grep RUNNING
  - Task Scheduler:    run as scheduled task with no interaction
  - NSSM service:      install as Windows Service
""")


# =====================================================================
# MAIN
# =====================================================================
COMMANDS = {
    "start": cmd_start,
    "stop": cmd_stop,
    "restart": cmd_restart,
    "status": cmd_status,
    "health": cmd_health,
    "rules": cmd_rules,
    "logs": cmd_logs,
    "watchdog": cmd_watchdog,
    "build": cmd_build,
    "mouth": cmd_mouth,
    "install": cmd_install,
    "uninstall": cmd_uninstall,
    "help": cmd_help,
}


def main():
    if len(sys.argv) < 2:
        cmd_help(None)
        return 0

    cmd = sys.argv[1].lower()
    args = sys.argv[2:]

    if cmd not in COMMANDS:
        print(f"Unknown command: {cmd}")
        print("Run 'python aegis_daemon.py help' for available commands.")
        return 1

    try:
        result = COMMANDS[cmd](args)
        return 0 if result is None or result else 1
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as e:
        log(f"Error: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
