import json, os, time
from datetime import datetime
from pathlib import Path

VERSION = "2.1.0"
START_TIME = datetime.now()

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

RULES_FILE = str(PROJECT_ROOT / "Rules.json")

# =====================================================================
# AEGIS NIDS COMMAND CENTER (Legacy Dashboard) v2.1
# =====================================================================
# รายงานผลการตรวจจับและสถานะระบบแบบรวมศูนย์
# ใช้แสดงผลบนคอนโซลแบบ TUI/Legacy หลังจากระบบทำงานแล้ว
# รองรับการดู:
#   - สถิติการตรวจจับรวม
#   - ตารางเหตุการณ์ล่าสุด
#   - ตัวชี้ DEFCON
#   - สถานะความพร้อม (readiness gate)
#   - ตารางการทำงานของ subsystem
# ---
# Compile:  not required (Python script)
# Run:      python scripts\Dashboard.py
# ----------------------------------------------------------------

# โมดูลเก็บสถานะระบบระดับคณะ

# ฟิกซ์: เพิ่มการรองรับการเข้ารหัส UTF-8 บน Windows
import sys
import io
for _s in ("stdout", "stderr"):
    _stream = getattr(sys, _s, None)
    if _stream is None:
        continue
    _reconf = getattr(_stream, "reconfigure", None)
    if _reconf is not None:
        try:
            _reconf(encoding="utf-8", errors="replace")
        except Exception:
            pass
    else:
        # Python < 3.7 fallback
        import io as _io
        setattr(sys, _s, _io.TextIOWrapper(_stream.buffer, encoding="utf-8", errors="replace", line_buffering=True))
# ----------------------------------------------------------------

# --- [ COLOR PALETTE ] ---
# ใช้สีสอดคล้องกับ AEGIS NIDS visual design language
class C:
    CYAN = '\033[96;1m'
    BOLD = '\033[1m'
    RED = '\033[91;1m'
    GREEN = '\033[92;1m'
    YELLOW = '\033[93;1m'
    DIM = '\033[2m'
    RESET = '\033[0m'
    ORANGE = '\033[38;5;208m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'

# --- [ DEFCON LEVELS ]---
# สีสำหรับแต่ละระดับ DEFCON
DEFCON_COLORS = {
    1: C.MAGENTA,  # MAXIMUM
    2: C.RED,      # SEVERE
    3: C.ORANGE,   # HIGH
    4: C.YELLOW,   # ELEVATED
    5: C.GREEN,    # SAFE
}

DEFCON_LABELS = {
    1: "MAXIMUM",
    2: "SEVERE",
    3: "HIGH",
    4: "ELEVATED",
    5: "SAFE",
}

# --- [ MAIN DISPLAY FUNCTIONS ] ---

COMPONENT_LABELS = {
    "control": "CONTROL DAEMON",
    "cpp": "C++ BRIDGE",
    "forensic": "FORENSIC PLANE",
    "go": "GO NOSE",
    "rust_pep": "RUST MOUTH / PEP",
    "tier3": "PYTHON BRAIN / TIER3",
    "zig": "ZIG CORE",
}

def clear_screen():
    """Clear console screen (Windows / Unix compatible)."""
    import os
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Print standardized header for AEGIS dashboards."""
    clear_screen()
    print(f"{C.CYAN}╔{'═'*78}╗{C.RESET}")
    header_text = f"🛡️  AEGIS NIDS COMMAND CENTER v{VERSION} | TIME: {datetime.now().strftime('%H:%M:%S')}"
    print(f"{C.CYAN}║{C.RESET} {header_text.ljust(76)} {C.CYAN}║{C.RESET}")
    print(f"{C.CYAN}╚{'═'*78}╝{C.RESET}")
    print()


def fetch_snapshot():
    """Read the authoritative runtime snapshot through aegisctl."""
    import subprocess
    import sys

    cli = PROJECT_ROOT / "tools" / "aegisctl.py"

    try:
        result = subprocess.run(
            [sys.executable, str(cli), "snapshot"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except Exception as exc:
        return {
            "available": False,
            "reason": "aegisctl_snapshot_exception",
            "error": str(exc),
        }

    output = result.stdout.strip()

    if not output:
        return {
            "available": False,
            "reason": "aegisctl_snapshot_empty",
            "exit_code": result.returncode,
            "stderr": result.stderr.strip(),
        }

    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        return {
            "available": False,
            "reason": "aegisctl_snapshot_invalid_json",
            "error": str(exc),
            "output": output[-500:],
        }

    if not isinstance(data, dict):
        return {
            "available": False,
            "reason": "aegisctl_snapshot_invalid_payload",
        }

    return data


def get_defcon_info(snapshot=None):
    """Derive display-only DEFCON from authoritative runtime health."""
    snapshot = snapshot or {}
    health = snapshot.get("health") or {}

    state = str(
        health.get("state", health.get("runtime_state", "UNKNOWN"))
    ).upper()
    degraded = bool(health.get("degraded", True))

    if state != "RUNNING":
        return 2, "SEVERE"

    if degraded:
        return 3, "HIGH"

    return 5, "SAFE"


def main():
    """Render a read-only dashboard from the daemon-owned snapshot."""
    try:
        while True:
            snapshot = fetch_snapshot()

            clear_screen()
            print_header()

            if not snapshot.get("available", False):
                print(f"{C.RED}{C.BOLD}[ CONTROL CENTER UNAVAILABLE ]{C.RESET}")
                print(
                    f"  Reason: "
                    f"{snapshot.get('reason', 'unknown')}"
                )
                if snapshot.get("error"):
                    print(f"  Error: {snapshot['error']}")
                print()
                print(
                    "  This dashboard does not use local logs or process scans "
                    "as runtime truth."
                )
                time.sleep(2)
                continue

            health = snapshot.get("health") or {}
            metrics = snapshot.get("metrics") or {}
            forensic = snapshot.get("forensic") or {}
            enforcement = snapshot.get("enforcement") or {}
            authority = snapshot.get("authority") or {}
            presentation = snapshot.get("presentation") or {}

            defcon_level, defcon_label = get_defcon_info(snapshot)
            defcon_color = DEFCON_COLORS.get(defcon_level, C.DIM)

            print(
                f"{C.BOLD}DEFCON {defcon_level}: "
                f"{defcon_color}{defcon_label}{C.RESET}"
            )
            print()

            print(f"{C.BOLD}[ SYSTEM STATE ]{C.RESET}")
            print(
                f"  Runtime: "
                f"{health.get('state', health.get('runtime_state', 'UNKNOWN'))}"
            )
            print(f"  Runtime readiness: {not health.get('degraded', True)}")
            print(f"  Daemon PID: {health.get('pid', '-')}")
            print(f"  Version: {health.get('version', '-')}")
            print(f"  Uptime: {health.get('uptime_ms', 0)} ms")
            print()

            print(f"{C.BOLD}[ SUBSYSTEM READINESS ]{C.RESET}")
            subsystems = health.get("subsystems") or {}
            for name, item in subsystems.items():
                if not isinstance(item, dict):
                    continue
                label = COMPONENT_LABELS.get(name, name.upper())
                print(
                    f"  {label:<24} "
                    f"{item.get('state', 'UNKNOWN'):<10} "
                    f"version={item.get('version', '-')}"
                )
            print()

            print(f"{C.BOLD}[ DATA PLANE ]{C.RESET}")
            data_plane = health.get("data_plane") or {}
            print(
                f"  Frames read: {data_plane.get('nose_frames_read', 0)}"
            )
            print(
                f"  Frames submitted: "
                f"{data_plane.get('nose_frames_submitted', 0)}"
            )
            print(
                f"  Frames dropped: "
                f"{data_plane.get('nose_frames_dropped', 0)}"
            )
            print(
                f"  Nose connected: "
                f"{data_plane.get('nose_connected', False)}"
            )
            print()

            print(f"{C.BOLD}[ ENFORCEMENT AUTHORITY ]{C.RESET}")
            print(
                f"  Canonical authority: "
                f"{authority.get('canonical', 'UNKNOWN')}"
            )
            print(
                f"  Authority invariant: "
                f"{authority.get('invariant', 'UNKNOWN')}"
            )
            print(
                f"  Prevention gate: "
                f"{str(enforcement.get('prevention_gate', 'closed')).upper()}"
            )
            print(
                f"  Enforcement mode: "
                f"{str(enforcement.get('enforcement_mode', 'UNKNOWN')).upper()}"
            )
            print(
                f"  Provider ready: "
                f"{enforcement.get('provider_ready', False)}"
            )
            print(
                f"  Host effect capable: "
                f"{enforcement.get('host_effect_capable', False)}"
            )
            print(
                f"  Host effect: "
                f"{presentation.get('host_effect', 'NOT_PROVEN')}"
            )
            print(
                f"  Presentation mode: "
                f"{presentation.get('mode', 'OBSERVE_ONLY')}"
            )
            print()

            print(f"{C.BOLD}[ OVERALL STATISTICS ]{C.RESET}")
            print(
                f"  Detections: "
                f"{metrics.get('detections', 0)}"
            )
            print(
                f"  Events processed: "
                f"{metrics.get('events_processed', 0)}"
            )
            print(
                f"  Packets captured: "
                f"{metrics.get('packets_captured', 0)}"
            )
            print(
                f"  Flows active: "
                f"{metrics.get('flows_active', 0)}"
            )
            print(
                f"  Incidents open: "
                f"{metrics.get('incidents_open', 0)}"
            )
            print(
                f"  Runtime dropped/errors: "
                f"{health.get('counters', {}).get('dropped', 0)}/"
                f"{health.get('counters', {}).get('errors', 0)}"
            )
            print()

            print(f"{C.BOLD}[ FORENSIC PLANE ]{C.RESET}")
            print(
                f"  Integrity: "
                f"{forensic.get('integrity', 'UNKNOWN')}"
            )
            print(
                f"  Verified: "
                f"{forensic.get('verified', False)}"
            )
            print(
                f"  Records: "
                f"{forensic.get('records', 0)}"
            )
            print()

            print(
                f"{C.DIM}Read-only view from "
                f"tools/aegisctl.py snapshot | Ctrl+C to exit{C.RESET}"
            )

            time.sleep(1)

    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Dashboard stopped.{C.RESET}")


if __name__ == "__main__":
    main()