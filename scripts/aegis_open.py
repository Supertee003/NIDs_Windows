"""AEGIS system opener: one command to open (or inspect) the whole system.

Topology (current production, not the deprecated all-background model):
  - Windows service AegisNids (ETW/FIM/registry/nose-reader/pipeline, LocalSystem)
  - Go nose capture (this host's traffic -> daemon pipe; any user that may write it)
  - Python brain Tier-2 analytics (UDP 127.0.0.1:9999, advisory only)

Usage:
  python scripts/aegis_open.py status      # read-only: check everything (default)
  python scripts/aegis_open.py open        # start whatever is missing, then verify
  python scripts/aegis_open.py close       # stop supervised nose+brain (service stays up)
  python scripts/aegis_open.py close --with-service
  python scripts/aegis_open.py status --json

Safety rules baked in from incident history:
  - status never starts/stops anything (safe to run any time, any user).
  - open is idempotent: running components are SKIPPED, never restarted.
  - service stop/start uses deadline loops (stops hang) and verifies state.
  - nose starts with CWD=repo root (otherwise it cannot find
    configs/Rules.json and runs ruleless) and detached (survives us).
  - interface: $AEGIS_NOSE_IFACE wins, else nose auto-selects; frames
    flowing (not the flag) decides success.
  - logs go to C:\\Temp\\aegis_open.log, never the repo tree.
  - exit 0 = all green, 1 = something failed, 2 = partial (some skipped).
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

SERVICE_NAME = "AegisNids"
NOSE_EXE = REPO_ROOT / "nose" / "aegis-nose.exe"
BRAIN_SCRIPT = REPO_ROOT / "brain" / "windows_brain.py"
BRAIN_PORT = 9999
OPEN_LOG = Path(r"C:\Temp\aegis_open.log")
START_TIMEOUT_S = 180
STOP_TIMEOUT_S = 180
GUI_EXE = REPO_ROOT / "aegis_dashboard" / "target" / "release" / "aegis_dashboard.exe"
TUI_EXE = REPO_ROOT / "mouth" / "target" / "release" / "windows_sec_monitor.exe"
WEB_PORT = int(os.environ.get("DASHBOARD_PORT", "5000"))
WEB_URL = "http://127.0.0.1:%d/" % WEB_PORT


def log_line(text: str) -> None:
    try:
        with OPEN_LOG.open("a", encoding="utf-8") as handle:
            handle.write("%s %s\n" % (datetime.datetime.now().isoformat(timespec="seconds"), text))
    except OSError:
        pass


def run(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    """Run and capture (text). Never raises on command failure."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)


def wait_for(predicate, timeout_s: int, poll_s: float = 5.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(poll_s)
    return predicate()


# --------------------------------------------------------------------------
# Pure helpers (unit-pinned; no system touch)
# --------------------------------------------------------------------------

def resolve_nose_iface(env: dict | None = None) -> list[str]:
    """Extra nose argv: explicit interface wins, else auto-select.

    Returns [] for auto-select so a bad env value can never break the
    default; the frames-flowing check below is the real gate anyway.
    AEGIS_CAPTURE_IFACE is honored as a legacy alias (run_aegis.bat era).
    """
    env = os.environ if env is None else env
    iface = (env.get("AEGIS_NOSE_IFACE") or env.get("AEGIS_CAPTURE_IFACE") or "").strip()
    if iface:
        return ["-iface", iface]
    return []


def summarize(label: str, ok: bool | None, detail: str = "") -> dict:
    """One status row: ok True/False, None means skipped/not-applicable."""
    return {"check": label, "ok": ok, "detail": detail}


def overall_exit(rows: list[dict]) -> int:
    if all(r["ok"] is True for r in rows):
        return 0
    if any(r["ok"] is False for r in rows):
        return 1
    return 2


def render(rows: list[dict], as_json: bool) -> str:
    if as_json:
        return json.dumps({"rows": rows}, indent=1, sort_keys=True)
    lines = []
    for row in rows:
        mark = "OK  " if row["ok"] is True else ("FAIL" if row["ok"] is False else "SKIP")
        detail = (" - %s" % row["detail"]) if row.get("detail") else ""
        lines.append("[%s] %s%s" % (mark, row["check"], detail))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Live probes (read-only unless stated)
# --------------------------------------------------------------------------

def control_api():
    from aegisctl.api.control_api import query_control
    return query_control


def service_state() -> str:
    rc, out, _ = run(["sc.exe", "query", SERVICE_NAME], timeout=30)
    if rc != 0:
        return "UNKNOWN"
    upper = out.upper()
    if "RUNNING" in upper:
        return "RUNNING"
    if "STOPPED" in upper:
        return "STOPPED"
    return "UNKNOWN"


def process_running(exe_name: str) -> bool:
    return len(_pids_by_name(exe_name)) > 0


def udp_port_owned(port: int) -> bool:
    rc, out, _ = run(
        ["powershell", "-NoProfile", "-Command",
         "Get-NetUDPEndpoint -LocalPort %d -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess" % port],
        timeout=30,
    )
    return rc == 0 and bool(out.strip())


def tcp_port_responds(port: int, path: str = "/api/snapshot", timeout_s: float = 8.0) -> bool:
    """Pure-stdlib HTTP probe: True only when OUR console answers."""
    import urllib.request
    import urllib.error
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=timeout_s) as response:
            if response.status != 200:
                return False
            body = response.read(4096).decode("utf-8", errors="replace")
            return "aegis.operator.snapshot" in body or "AEGIS" in body
    except Exception:
        return False


def _detached(args: list[str], cwd: Path) -> bool:
    try:
        subprocess.Popen(
            args, cwd=str(cwd),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        return True
    except OSError:
        return False


# Display surfaces and their stop matchers (exact tool identity only —
# the same precision rule as nose/brain: never blanket-kill consoles).
_DISPLAY_MATCH = {
    "web": ("python", "web_dashboard"),
    "gui": ("exe", "aegis_dashboard"),
    "tui": ("exe", "windows_sec_monitor"),
    "terminal": ("python", "dashboard --watch"),
}


def display_running(name: str) -> bool:
    if name == "web":
        return tcp_port_responds(WEB_PORT)
    if name == "gui":
        return process_running("aegis_dashboard")
    if name == "tui":
        return process_running("windows_sec_monitor")
    return False  # terminal windows are not tracked; always fresh


def start_display(name: str, open_browser: bool = True) -> dict:
    if display_running(name):
        return summarize("start display %s" % name, None, "already running (skipped)")
    if name == "web":
        env = dict(os.environ)
        env["DASHBOARD_PORT"] = str(WEB_PORT)
        try:
            proc = subprocess.Popen(
                [sys.executable, "-m", "aegisctl.web_dashboard.app"],
                cwd=str(TOOLS_DIR), env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            )
        except OSError as exc:
            return summarize("start display web", False, "spawn failed: %s" % exc)
        if wait_for(lambda: tcp_port_responds(WEB_PORT), 60):
            if open_browser:
                try:
                    import webbrowser
                    webbrowser.open(WEB_URL)
                except Exception:
                    pass
            return summarize("start display web", True, "%s serving (pid %s)" % (WEB_URL, proc.pid))
        return summarize("start display web", False, "no snapshot answer in 60s")
    if name == "gui":
        if not GUI_EXE.is_file():
            return summarize("start display gui", False, "missing: %s" % GUI_EXE)
        if not _detached([str(GUI_EXE)], REPO_ROOT):
            return summarize("start display gui", False, "spawn failed")
        time.sleep(6)
        if process_running("aegis_dashboard"):
            return summarize("start display gui", True, "window open (eyeball check)")
        return summarize("start display gui", False, "exited immediately")
    if name == "tui":
        if not TUI_EXE.is_file():
            return summarize("start display tui", False, "missing: %s" % TUI_EXE)
        if not _detached(["cmd", "/c", "start", "AEGIS MOUTH", str(TUI_EXE)], REPO_ROOT):
            return summarize("start display tui", False, "spawn failed")
        time.sleep(4)
        if process_running("windows_sec_monitor"):
            return summarize("start display tui", True, "console open")
        return summarize("start display tui", False, "exited immediately")
    if name == "terminal":
        if not _detached(
            ["cmd", "/c", "start", "AEGIS DASHBOARD",
             sys.executable, "tools\\aegisctl.py", "dashboard", "--watch"],
            REPO_ROOT,
        ):
            return summarize("start display terminal", False, "spawn failed")
        return summarize("start display terminal", True, "watch window open (Ctrl+C there stops it)")
    return summarize("start display %s" % name, False, "unknown surface")


def stop_display(name: str) -> dict:
    """Stop one display surface by exact tool identity. Never the service."""
    if name not in _DISPLAY_MATCH:
        return summarize("stop display %s" % name, False, "unknown surface")
    kind, fragment = _DISPLAY_MATCH[name]
    if kind == "exe":
        pids = _pids_by_name(fragment)
    else:
        pids = _pids_by_cmdline(fragment)
    if not pids:
        return summarize("stop display %s" % name, True, "was not running")
    killed, failed = _kill_pids(pids)
    if kind == "exe":
        gone = [p for p in killed if p not in _pids_by_name(fragment)]
    else:
        gone = [p for p in killed if p not in _pids_by_cmdline(fragment)]
    still = [p for p in pids if p not in gone]
    if not still:
        return summarize("stop display %s" % name, True, "stopped %s" % ",".join(map(str, gone or killed)))
    return summarize("stop display %s" % name, False, "cannot stop %s (elevate?)" % ",".join(map(str, still)))


def cmd_displays(args) -> int:
    wanted = [a for a in ("web", "gui", "tui", "terminal") if getattr(args, a, False)]
    if not wanted and not getattr(args, "stop", False):
        wanted = ["web", "gui", "tui", "terminal"]
    rows = []
    if getattr(args, "stop", False):
        targets = wanted or ["web", "gui", "tui", "terminal"]
        for name in targets:
            rows.append(stop_display(name))
        print(render(rows, bool(args.json)))
        for row in rows:
            log_line("displays %s ok=%s %s" % (row["check"], row["ok"], row.get("detail", "")))
        return overall_exit(rows)
    for name in wanted:
        rows.append(start_display(name, open_browser=not getattr(args, "no_browser", False)))
    print(render(rows, bool(args.json)))
    for row in rows:
        log_line("displays %s ok=%s %s" % (row["check"], row["ok"], row.get("detail", "")))
    return overall_exit(rows)


def daemon_snapshot() -> dict:
    try:
        query_control = control_api()
    except Exception:
        return {}
    try:
        health = query_control("system.health") or {}
    except Exception:
        return {}
    return health if isinstance(health, dict) else {}


def check_service() -> dict:
    state = service_state()
    if state == "RUNNING":
        return summarize("service AegisNids running", True, state)
    return summarize("service AegisNids running", False, "state=%s" % state)


def check_daemon() -> dict:
    health = daemon_snapshot()
    if not health:
        # Unknown, not failed: a contended pipe (e.g. a full-ring verify
        # holding the forensic mutex under load) times out the client
        # while the daemon is healthy. Reporting failure here lied
        # during load spikes; None keeps it an explicit unknown.
        return summarize("daemon control plane reachable", None, "no response (unknown, not failed)")
    state = health.get("state", "?")
    rules = health.get("rules_loaded", "?")
    workers = health.get("workers", {}) if isinstance(health.get("workers"), dict) else {}
    ready = sorted(k for k, v in workers.items() if v is True)
    if state == "RUNNING":
        return summarize("daemon RUNNING, rules=%s, ready=%d workers" % (rules, len(ready)), True,
                         "defcon=%s" % health.get("defcon_label", "?"))
    return summarize("daemon RUNNING", False, "state=%s" % state)


def check_nose() -> dict:
    if not process_running("aegis-nose"):
        return summarize("nose capture process", False, "not running")
    try:
        query_control = control_api()
        data = query_control("system.health") or {}
        if not data:
            return summarize("nose capture counters", None, "health unreadable (unknown, not zero)")
        dp = data.get("data_plane", {}) if isinstance(data, dict) else {}
        read = int(dp.get("nose_frames_read", 0) or 0)
    except Exception:
        return summarize("nose capture process", None, "running, counters unreadable")
    if read > 0:
        return summarize("nose capture flowing", True, "frames_read=%d" % read)
    return summarize("nose capture flowing", False, "process up but frames_read=0")


def check_brain() -> dict:
    if not udp_port_owned(BRAIN_PORT):
        return summarize("brain listener :9999", False, "no listener")
    return summarize("brain listener :9999", True, "port owned")


# --------------------------------------------------------------------------
# Mutations (open/close only)
# --------------------------------------------------------------------------

def start_service() -> dict:
    if service_state() == "RUNNING":
        return summarize("start service", None, "already RUNNING (skipped)")
    rc, _, err = run(["sc.exe", "start", SERVICE_NAME], timeout=60)
    if rc != 0:
        return summarize("start service", False, "sc start failed (admin?): %s" % err.strip()[:160])
    if wait_for(lambda: service_state() == "RUNNING", START_TIMEOUT_S):
        return summarize("start service", True, "RUNNING")
    return summarize("start service", False, "did not reach RUNNING in %ds" % START_TIMEOUT_S)


def stop_service() -> dict:
    if service_state() == "STOPPED":
        return summarize("stop service", None, "already STOPPED (skipped)")
    run(["sc.exe", "stop", SERVICE_NAME], timeout=60)
    if wait_for(lambda: service_state() == "STOPPED", STOP_TIMEOUT_S):
        return summarize("stop service", True, "STOPPED")
    return summarize("stop service", False, "still not STOPPED after %ds (may need SCM/taskkill)" % STOP_TIMEOUT_S)


def start_nose() -> dict:
    if process_running("aegis-nose"):
        return summarize("start nose", None, "already running (skipped)")
    if not NOSE_EXE.is_file():
        return summarize("start nose", False, "binary missing: %s" % NOSE_EXE)
    try:
        subprocess.Popen(
            [str(NOSE_EXE), "-capture"] + resolve_nose_iface(),
            cwd=str(REPO_ROOT),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        )
    except OSError as exc:
        return summarize("start nose", False, "spawn failed: %s" % exc)
    time.sleep(15)
    if not process_running("aegis-nose"):
        return summarize("start nose", False, "exited immediately (see daemon pipe/Npcap)")
    return summarize("start nose", True, "process alive; frames check in verify")


def start_brain() -> dict:
    if udp_port_owned(BRAIN_PORT):
        return summarize("start brain", None, "port owned (skipped)")
    if not BRAIN_SCRIPT.is_file():
        return summarize("start brain", False, "missing: %s" % BRAIN_SCRIPT)
    try:
        subprocess.Popen(
            [sys.executable, str(BRAIN_SCRIPT)],
            cwd=str(REPO_ROOT),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        )
    except OSError as exc:
        return summarize("start brain", False, "spawn failed: %s" % exc)
    time.sleep(8)
    if udp_port_owned(BRAIN_PORT):
        return summarize("start brain", True, "listener present")
    return summarize("start brain", False, "no listener after start (see script output)")


def _pids_by_name(exe_name: str) -> list[int]:
    rc, out, _ = run(
        ["powershell", "-NoProfile", "-Command",
         "Get-Process %s -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id" % exe_name],
        timeout=30,
    )
    if rc != 0:
        return []
    return [int(line.strip()) for line in out.splitlines() if line.strip().isdigit()]


def _pids_by_cmdline(fragment: str) -> list[int]:
    rc, out, _ = run(
        ["powershell", "-NoProfile", "-Command",
         "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { $_.CommandLine -like '*%s*' } | Select-Object -ExpandProperty ProcessId" % fragment],
        timeout=30,
    )
    if rc != 0:
        return []
    return [int(line.strip()) for line in out.splitlines() if line.strip().isdigit()]


def _kill_pids(pids: list[int]) -> tuple[list[int], list[int]]:
    """Returns (killed, surviving). A kill that fails (e.g. access denied
    on an elevated process) is reported, never mistaken for absence."""
    killed, surviving = [], []
    for pid in pids:
        rc, _, _ = run(
            ["powershell", "-NoProfile", "-Command",
             "Stop-Process -Id %d -Force" % pid],
            timeout=30,
        )
        (killed if rc == 0 else surviving).append(pid)
    time.sleep(2)
    return killed, surviving


def stop_supervised() -> list[dict]:
    """Stop nose+brain supervised processes. Never touches the service."""
    rows = []
    nose = _pids_by_name("aegis-nose")
    if not nose:
        rows.append(summarize("stop nose", True, "was not running"))
    else:
        killed, failed = _kill_pids(nose)
        gone = [p for p in killed if p not in _pids_by_name("aegis-nose")]
        still = [p for p in nose if p not in gone]
        if not still:
            rows.append(summarize("stop nose", True, "stopped pid(s) %s" % ",".join(map(str, gone or killed))))
        else:
            rows.append(summarize("stop nose", False, "cannot stop pid(s) %s (elevate?) kill_rc_failed=%s" % (",".join(map(str, still)), ",".join(map(str, failed)) or "none")))
    brain = _pids_by_cmdline("windows_brain")
    if not brain:
        rows.append(summarize("stop brain", True, "was not running"))
    else:
        killed, failed = _kill_pids(brain)
        gone = [p for p in killed if p not in _pids_by_cmdline("windows_brain")]
        still = [p for p in brain if p not in gone]
        if not still:
            rows.append(summarize("stop brain", True, "stopped pid(s) %s" % ",".join(map(str, gone or killed))))
        else:
            rows.append(summarize("stop brain", False, "cannot stop pid(s) %s (elevate?) kill_rc_failed=%s" % (",".join(map(str, still)), ",".join(map(str, failed)) or "none")))
    return rows


def cmd_status(args) -> int:
    rows = [check_service(), check_daemon(), check_nose(), check_brain()]
    print(render(rows, bool(args.json)))
    for row in rows:
        log_line("%s ok=%s %s" % (row["check"], row["ok"], row.get("detail", "")))
    return overall_exit(rows)


def cmd_open(args) -> int:
    rows = [start_service(), start_nose(), start_brain()]
    time.sleep(5)
    rows += [check_service(), check_daemon(), check_nose(), check_brain()]
    print(render(rows, bool(args.json)))
    for row in rows:
        log_line("open %s ok=%s %s" % (row["check"], row["ok"], row.get("detail", "")))
    return overall_exit([r for r in rows if r["ok"] is not None])


def cmd_close(args) -> int:
    rows = stop_supervised()
    if args.with_service:
        rows.append(stop_service())
    else:
        rows.append(summarize("service left running", True, "detection continues (use --with-service to stop)"))
    # After close, absence is success: invert the running-checks.
    nose_gone = not process_running("aegis-nose")
    brain_gone = not udp_port_owned(BRAIN_PORT)
    rows.append(summarize("nose stopped", True if nose_gone else False, "" if nose_gone else "still running"))
    rows.append(summarize("brain stopped", True if brain_gone else False, "" if brain_gone else "port still owned"))
    print(render(rows, bool(args.json)))
    for row in rows:
        log_line("close %s ok=%s %s" % (row["check"], row["ok"], row.get("detail", "")))
    return overall_exit(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis_open.py", description="Open, inspect, or close the AEGIS system")
    sub = parser.add_subparsers(dest="cmd")
    for name, func, help_text in (
        ("status", cmd_status, "check everything (read-only, default)"),
        ("open", cmd_open, "start whatever is missing, then verify"),
        ("close", cmd_close, "stop supervised nose+brain (service stays up)"),
        ("displays", cmd_displays, "start/stop the web+gui+tui+terminal displays"),
    ):
        parser_sub = sub.add_parser(name, help=help_text)
        parser_sub.add_argument("--json", action="store_true")
        parser_sub.set_defaults(func=func)
    close_parser = sub.choices["close"]
    close_parser.add_argument("--with-service", action="store_true", help="also stop the AegisNids service")
    displays_parser = sub.choices["displays"]
    for flag in ("web", "gui", "tui", "terminal"):
        displays_parser.add_argument("--" + flag, action="store_true", help="only this surface")
    displays_parser.add_argument("--stop", action="store_true", help="stop instead of start")
    displays_parser.add_argument("--no-browser", action="store_true", help="do not open a browser for web")
    parser.set_defaults(cmd="status", func=cmd_status, json=False)
    args = parser.parse_args(argv)
    return int(args.func(args)) or 0


if __name__ == "__main__":
    raise SystemExit(main())
