"""AEGIS Pro Control Center console.

This is an operator control surface, not a second runtime authority.
Read-only views use aegisctl snapshot/health. Mutations are restricted to
Admin mode and are routed through the existing launcher/control contract.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "tools" / "aegisctl.py"
LAUNCHER = ROOT / "scripts" / "aegis.ps1"

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
DIM = "\033[2m"


def color(text: str, code: str) -> str:
    return f"{code}{text}{RESET}"


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def run_cli(*args: str, json_output: bool = True) -> tuple[int, object | str]:
    command = [sys.executable, str(CLI), *args]
    proc = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    output = proc.stdout.strip()
    if json_output:
        try:
            return proc.returncode, json.loads(output)
        except json.JSONDecodeError:
            return proc.returncode, output
    return proc.returncode, output


def snapshot() -> dict:
    code, data = run_cli("snapshot")
    if code == 0 and isinstance(data, dict):
        return data
    return {"available": False, "reason": "control_center_unavailable", "detail": data}


def health_payload(data: dict) -> dict:
    return data.get("health", {}) if isinstance(data, dict) else {}


def status_word(state: str, good: bool = True) -> str:
    if state in {"RUNNING", "READY", "OK", "PASS"} and good:
        return color(state, GREEN)
    if state in {"DEGRADED", "WARNING", "UNKNOWN"} or not good:
        return color(state, YELLOW)
    return color(state, RED)


def is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def require_admin(role: str) -> bool:
    if role != "admin":
        print(color("ADMIN ACTION BLOCKED: start/stop/reload requires --role admin", RED))
        return False
    if os.name == "nt" and not is_admin():
        print(color("ADMIN ACTION BLOCKED: PowerShell must be started as Administrator", RED))
        return False
    return True


def print_header(role: str) -> None:
    print("=" * 78)
    print(f"  {BOLD}{CYAN}AEGIS NIDS PRO CONTROL CENTER{RESET}    role={role.upper()}")
    print("  One control surface | Control Center is the runtime authority")
    print("=" * 78)


def print_overview(data: dict) -> None:
    health = health_payload(data)
    if not data.get("available", False):
        print(color("CONTROL CENTER: UNAVAILABLE", RED))
        print(f"  reason: {data.get('reason', 'unknown')}")
        return
    state = str(health.get("state", "UNKNOWN"))
    degraded = bool(health.get("degraded", True))
    print(f"Runtime       : {status_word(state, not degraded)}")
    print(f"Overall gate  : {status_word('DEGRADED' if degraded else 'READY', not degraded)}")
    print(f"PID / version : {health.get('pid', '-')} / {health.get('version', '-')}")
    print(f"Uptime        : {health.get('uptime_ms', 0)} ms")
    workers = health.get("workers", {})
    names = ["pipeline_ready", "sensor_ready", "nose_ready", "etw_ready", "fim_ready", "registry_ready"]
    ready = sum(workers.get(name) is True for name in names)
    print(f"Workers       : {ready}/{len(names)} ready | failure_mask={workers.get('failure_mask', 0)}")
    print(f"Failure       : {', '.join(workers.get('failure_reasons', [])) or 'none'}")
    data_plane = health.get("data_plane", {})
    print(f"Data plane    : read={data_plane.get('nose_frames_read', 0)} submitted={data_plane.get('nose_frames_submitted', 0)} dropped={data_plane.get('nose_frames_dropped', 0)}")
    print(f"Exactly once  : duplicate={data_plane.get('nose_duplicate_event_ids', 0)} non_monotonic={data_plane.get('nose_non_monotonic_event_ids', 0)}")
    forensic = data.get("forensic", {})
    print(f"Forensics     : {forensic.get('integrity', 'unknown')} | records={forensic.get('records', 0)}")


def print_components(data: dict) -> None:
    health = health_payload(data)
    print("\nCOMPONENT CONTROL MAP")
    print("-" * 78)
    print(f"{'Component':<16} {'State':<14} {'PID':<10} {'Version':<10} Error")
    for name, item in (health.get("subsystems") or {}).items():
        if not isinstance(item, dict):
            continue
        state = str(item.get("state", "UNKNOWN"))
        print(f"{name:<16} {state:<23} {str(item.get('pid') or '-'):<10} {str(item.get('version') or '-'):<10} {item.get('error') or '-'}")


def print_mouth_nose(data: dict) -> None:
    health = health_payload(data)
    subsystems = health.get("subsystems") or {}
    workers = health.get("workers") or {}
    print("\nMOUTH / NOSE DATA PATH")
    print("-" * 78)
    nose = subsystems.get("go", {})
    print(f"NOSE   : {nose.get('state', 'UNKNOWN')} | worker={status_word('READY' if workers.get('nose_ready') else 'NOT READY', workers.get('nose_ready') is True)}")
    print(f"         connected={health.get('data_plane', {}).get('nose_connected', False)}")
    print(f"         frames read={health.get('data_plane', {}).get('nose_frames_read', 0)} submitted={health.get('data_plane', {}).get('nose_frames_submitted', 0)}")
    print(f"MOUTH  : {subsystems.get('rust_pep', {}).get('state', 'UNKNOWN')} | Tier3={health.get('tier3', {}).get('state', 'UNKNOWN')}")
    print(f"         enforcement capability={health.get('capabilities', {}).get('wfp', False)}")
    print("Path    : NOSE ingress -> canonical event -> detection -> policy -> MOUTH/PEP -> forensic")


def action_start(role: str) -> None:
    if not require_admin(role):
        return
    code, output = run_cli("start", "--all", json_output=False)
    print(output)
    print(f"start exit={code}; verify with health before operation")


def action_rules_reload(role: str) -> None:
    if not require_admin(role):
        return
    code, output = run_cli("rules", "validate", json_output=False)
    print(output)
    if code != 0:
        print(color("Reload blocked: rule validation failed", RED))
        return
    code, output = run_cli("rules", "reload", json_output=False)
    print(output)
    print(f"reload exit={code}")


def action_stop(role: str) -> None:
    if not require_admin(role):
        return
    stop_script = ROOT / "scripts" / "stop_aegis.bat"
    if not stop_script.exists():
        print(color("Stop unavailable: canonical stop script not found", RED))
        return
    proc = subprocess.run(["cmd", "/c", str(stop_script), "--force"], cwd=ROOT, text=True)
    print(f"stop exit={proc.returncode}")


def menu(role: str, interval: float) -> None:
    while True:
        clear()
        data = snapshot()
        print_header(role)
        print_overview(data)
        print_mouth_nose(data)
        print("\nCOMMANDS")
        print("  1  Refresh authoritative snapshot")
        print("  2  Component/readiness detail")
        print("  3  Mouth/Nose data-path detail")
        print("  4  Events statistics")
        print("  5  Forensic verification")
        print("  6  Open legacy TUI (compatibility)")
        if role == "admin":
            print("  A  Admin: start all runtime components")
            print("  R  Admin: validate and reload rules")
            print("  S  Admin: stop runtime")
        print("  0  Exit")
        choice = input("\nSelect: ").strip().lower()
        if choice == "0":
            return
        if choice == "1":
            continue
        if choice == "2":
            print_components(data)
            input("\nPress Enter...")
        elif choice == "3":
            print_mouth_nose(data)
            input("\nPress Enter...")
        elif choice == "4":
            _, output = run_cli("events", "stats", "--json")
            print(json.dumps(output, indent=2) if isinstance(output, dict) else output)
            input("\nPress Enter...")
        elif choice == "5":
            code, output = run_cli("forensics", "verify", "--json")
            print(json.dumps(output, indent=2) if isinstance(output, dict) else output)
            print(f"exit={code}")
            input("\nPress Enter...")
        elif choice == "6":
            subprocess.run([sys.executable, str(ROOT / "scripts" / "aegis_console.py")], cwd=ROOT)
        elif choice == "a":
            action_start(role)
            input("\nPress Enter...")
        elif choice == "r":
            action_rules_reload(role)
            input("\nPress Enter...")
        elif choice == "s":
            action_stop(role)
            input("\nPress Enter...")
        else:
            print(color("Unknown option", YELLOW))
            time.sleep(0.8)


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS Pro Control Center")
    parser.add_argument("--role", choices=["operator", "admin"], default="operator")
    parser.add_argument("--mode", choices=["menu", "snapshot", "components", "mouth-nose"], default="menu")
    parser.add_argument("--interval", type=float, default=2.0, help="Reserved for future watch mode; menu refresh is on demand")
    args = parser.parse_args()
    if args.mode == "snapshot":
        data = snapshot()
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0 if data.get("available") else 3
    data = snapshot()
    if args.mode == "components":
        print_components(data)
        return 0
    if args.mode == "mouth-nose":
        print_mouth_nose(data)
        return 0
    menu(args.role, args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
