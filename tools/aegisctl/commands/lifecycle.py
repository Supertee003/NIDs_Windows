"""Start, stop, restart, watchdog commands."""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import threading
import time
from typing import Dict, List

from ..client import AegisClient, AegisCtlError
from ..config import (
    REPO_ROOT, COMPONENTS, SUBSYSTEMS, PID_DIR,
    WATCHDOG_INTERVAL, WATCHDOG_MAX_RESTARTS, WATCHDOG_RESTART_WINDOW,
)
from ..utils import (
    ensure_dirs, write_pid, read_pid, clear_pid, clear_all_pids,
    is_process_running, find_pid_by_pattern, cleanup_stale_pids,
)


def _start_subsystem(sub: Dict) -> tuple:
    name = sub["name"]
    pid = read_pid(name)
    if pid and is_process_running(pid):
        return True, pid

    existing_pid = find_pid_by_pattern(sub.get("exe", name))
    if existing_pid:
        write_pid(name, existing_pid)
        return True, existing_pid

    if name == "brain":
        script = REPO_ROOT / sub.get("script", "brain/windows_brain.py")
        cmd = [sys.executable, str(script)]
    else:
        exe = sub.get("exe")
        if not exe:
            return False, None
        cmd = [str(REPO_ROOT / exe)]

    try:
        kwargs = {
            "cwd": str(REPO_ROOT),
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        proc = subprocess.Popen(cmd, **kwargs)
        write_pid(name, proc.pid)
        return True, proc.pid
    except Exception as e:
        clear_pid(name)
        return False, None


def _stop_subsystem(sub: Dict) -> bool:
    name = sub["name"]
    stopped = False

    pid = read_pid(name)
    if pid and is_process_running(pid):
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
            stopped = True
        except ImportError:
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, timeout=5)
        except Exception:
            pass
        clear_pid(name)

    if not stopped and os.name == "nt":
        exe = sub.get("exe")
        if exe:
            subprocess.run(["taskkill", "/F", "/IM", exe], capture_output=True)

    clear_pid(name)
    return stopped


def cmd_start(args: argparse.Namespace) -> int:
    comp = getattr(args, "component", None)
    all_flag = getattr(args, "all", False)
    if comp and all_flag:
        print("ERROR: --component and --all are mutually exclusive", file=sys.stderr)
        return 2
    if not comp and not all_flag:
        print("ERROR: --component NAME or --all required", file=sys.stderr)
        return 2

    ensure_dirs()
    skip_build = getattr(args, "skip_build", False)

    cleaned = cleanup_stale_pids(SUBSYSTEMS)
    if cleaned:
        print(f"  Cleaned {len(cleaned)} stale PID file(s)")

    if not skip_build:
        print("Building...")
        result = subprocess.run(
            ["cargo", "build", "--release"],
            cwd=str(REPO_ROOT), capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"Build failed: {result.stderr[:200]}", file=sys.stderr)

    if comp:
        target = [s for s in SUBSYSTEMS if s["name"] == comp]
        if not target:
            print(f"ERROR: unknown component '{comp}'", file=sys.stderr)
            return 2
        subs = target
    else:
        subs = SUBSYSTEMS

    started = 0
    for sub in subs:
        success, pid = _start_subsystem(sub)
        if success:
            started += 1
            print(f"[OK]  {sub['name']} started (PID {pid})")
        else:
            print(f"[!]  {sub['name']} failed to start")
        time.sleep(1)

    print(f"\nStarted {started}/{len(subs)} subsystems")
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    comp = getattr(args, "component", None)
    all_flag = getattr(args, "all", False)
    if comp and all_flag:
        print("ERROR: --component and --all are mutually exclusive", file=sys.stderr)
        return 2
    if not comp and not all_flag:
        print("ERROR: --component NAME or --all required", file=sys.stderr)
        return 2

    force = getattr(args, "force", False)

    try:
        client = AegisClient()
        resp = client.send("daemon.shutdown")
        if resp.get("ok"):
            print("[OK]  Core daemon shutdown requested")
    except AegisCtlError:
        pass

    if force:
        for sub in reversed(SUBSYSTEMS):
            exe = sub.get("exe")
            if exe and os.name == "nt":
                subprocess.run(["taskkill", "/F", "/IM", exe], capture_output=True)

    time.sleep(2)
    clear_all_pids()
    print("[OK]  All subsystems stopped")
    return 0


def cmd_restart(args: argparse.Namespace) -> int:
    comp = getattr(args, "component", None)
    if not comp:
        print("ERROR: --component NAME required", file=sys.stderr)
        return 2
    cmd_stop(args)
    time.sleep(2)
    cmd_start(args)
    return 0


def _watchdog_loop(running: threading.Event) -> None:
    restart_counts: Dict[str, List[float]] = {}

    while running.is_set():
        for sub in SUBSYSTEMS:
            name = sub["name"]
            pid = read_pid(name)
            if pid and is_process_running(pid):
                continue

            existing = find_pid_by_pattern(sub.get("exe", name))
            if existing:
                write_pid(name, existing)
                continue

            now = time.time()
            if name not in restart_counts:
                restart_counts[name] = []
            restart_counts[name] = [
                t for t in restart_counts[name]
                if now - t < WATCHDOG_RESTART_WINDOW
            ]
            if len(restart_counts[name]) >= WATCHDOG_MAX_RESTARTS:
                print(f"[WATCHDOG] {name} exceeded max restarts -- giving up")
                continue

            print(f"[WATCHDOG] {name} crashed! Auto-restarting...")
            success, new_pid = _start_subsystem(sub)
            if success:
                restart_counts[name].append(now)
                print(f"[WATCHDOG] {name} restarted (PID {new_pid})")

        for _ in range(WATCHDOG_INTERVAL * 10):
            if not running.is_set():
                break
            time.sleep(0.1)


def cmd_watchdog(args: argparse.Namespace) -> int:
    running = threading.Event()
    running.set()

    def handle_signal(signum, frame):
        running.clear()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    print("[WATCHDOG] Starting watchdog...")
    _watchdog_loop(running)
    print("[WATCHDOG] Watchdog stopped")
    return 0


def register_commands() -> None:
    pass


def setup_subcommands(sub) -> None:
    p = sub.add_parser("start", help="Start AEGIS service")
    p.add_argument("--component", "-c")
    p.add_argument("--all", "-a", action="store_true")
    p.add_argument("--skip-build", action="store_true")

    p = sub.add_parser("stop", help="Stop AEGIS service")
    p.add_argument("--component", "-c")
    p.add_argument("--all", "-a", action="store_true")
    p.add_argument("--force", "-f", action="store_true")

    p = sub.add_parser("restart", help="Restart AEGIS service")
    p.add_argument("--component", "-c")

    sub.add_parser("watchdog", help="Run watchdog (auto-restart crashed subsystems)")
