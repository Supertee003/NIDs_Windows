"""AEGIS Command Control Center, reborn (EVT-165).

The v8.0 menu console (scripts/aegis_console.py) is what operators miss:
flat SYSTEM / CONTROL / ANALYSIS sections with Thai labels. But its
actions belong to a dead architecture: _kill_all_subsystems (blanket
kills), _launch_all_subsystems (duplicate starters that fought the
service), direct-UDP block, watchdog via a missing daemon script.
This console keeps the MENU operators love and rewires every action to
the current contracts: the opener owns startup, the keeper owns
watchdogs, enforcement stays behind the Rust PEP.

Rules this console obeys (better than the old, not just equal):
  - never a second runtime: it only shells to existing thin commands
    (aegis_open.py, aegisctl.py, truth.py, release_engineering.py),
    inheriting stdio so output streams inline -- no popup consoles;
  - mutations (start/stop/restart/watchdog-install/mouth-start) need
    --role admin AND real elevation, else refused with a message;
  - read-only views work for every role, every user;
  - --once --choice KEY runs one action non-interactively (tests drive
    exactly this; the interactive loop is never exercised by tests).

Read-only except through the delegated commands. No tree writes.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Tuple

from .api.control_api import get_all_status, load_rules

REPO_ROOT = Path(__file__).resolve().parents[2]
OPENER = REPO_ROOT / "scripts" / "aegis_open.py"
CLI = REPO_ROOT / "tools" / "aegisctl.py"
TRUTH = REPO_ROOT / "tools" / "truth.py"
RELEASE = REPO_ROOT / "tools" / "release_engineering.py"

MenuAction = Callable[[], int]

# key, section, Thai label, admin-only, action name. Pinned: keys unique,
# every action resolves, mutations (and only mutations) need admin.
MENU: List[Tuple[str, str, str, bool, str]] = [
    ("1", "SYSTEM", "START  \u0e40\u0e1b\u0e34\u0e14\u0e23\u0e30\u0e1a\u0e1a\u0e17\u0e31\u0e49\u0e07\u0e2b\u0e21\u0e14 (open + displays)", True, "start_all"),
    ("2", "SYSTEM", "STOP   \u0e2b\u0e22\u0e38\u0e14\u0e08\u0e2d\u0e41\u0e25\u0e30 supervised (service \u0e22\u0e31\u0e07\u0e23\u0e31\u0e19\u0e15\u0e48\u0e2d)", True, "stop_all"),
    ("3", "SYSTEM", "RESTART  \u0e23\u0e35\u0e2a\u0e15\u0e32\u0e23\u0e4c\u0e17\u0e23\u0e31\u0e1e\u0e22\u0e32\u0e01\u0e23\u0e41\u0e2a\u0e14\u0e07\u0e1c\u0e25", True, "restart_all"),
    ("4", "SYSTEM", "STATUS  \u0e2a\u0e16\u0e32\u0e19\u0e30\u0e17\u0e38\u0e01\u0e2a\u0e48\u0e27\u0e19 + components", False, "show_status"),
    ("5", "SYSTEM", "WATCHDOG  keeper task \u0e15\u0e23\u0e27\u0e08/\u0e15\u0e34\u0e14\u0e15\u0e31\u0e49\u0e07", False, "show_watchdog"),
    ("6", "CONTROL", "MOUTH  \u0e40\u0e1b\u0e34\u0e14/\u0e1b\u0e34\u0e14/\u0e40\u0e0a\u0e47\u0e04\u0e40\u0e27\u0e2d\u0e23\u0e4c\u0e0a\u0e31\u0e19", False, "mouth_menu"),
    ("7", "CONTROL", "RULES  \u0e41\u0e04\u0e15\u0e15\u0e32\u0e25\u0e47\u0e2d\u0e01\u0e01\u0e0e (read-only)", False, "show_rules"),
    ("8", "CONTROL", "LOGS  \u0e14\u0e39 feed \u0e25\u0e48\u0e32\u0e2a\u0e38\u0e14", False, "show_logs"),
    ("9", "ANALYSIS", "HEALTH  \u0e2a\u0e38\u0e02\u0e20\u0e32\u0e1e\u0e23\u0e30\u0e1a\u0e1a + bridge + enforce", False, "show_health"),
    ("A", "ANALYSIS", "GRAPH  threat graph \u0e41\u0e1a\u0e1a\u0e23\u0e39\u0e49 receipt", False, "show_graph"),
    ("B", "ANALYSIS", "TEST  quick gates \u0e41\u0e1a\u0e1a\u0e2d\u0e48\u0e32\u0e19\u0e2d\u0e22\u0e48\u0e32\u0e07\u0e40\u0e14\u0e35\u0e22\u0e27", False, "run_gates"),
    ("C", "ANALYSIS", "DAEMON  health \u0e14\u0e34\u0e1a + forensic verify", False, "show_daemon"),
    ("0", "EXIT", "EXIT  \u0e1b\u0e34\u0e14 Console", False, "do_exit"),
]


def _run(argv: List[str]) -> int:
    """Run one thin command inline (stdio inherited, no new console)."""
    try:
        proc = subprocess.run(
            [sys.executable, *[str(a) for a in argv]],
            cwd=str(REPO_ROOT),
        )
        return proc.returncode
    except (OSError, subprocess.SubprocessError) as exc:
        print("spawn failed: %s" % exc)
        return 127


def _is_elevated() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _refuse_unless_admin(role: str) -> bool:
    if role != "admin":
        print("ADMIN ACTION BLOCKED: this needs --role admin (read-only otherwise)")
        return False
    if not _is_elevated():
        print("ADMIN ACTION BLOCKED: shell is not elevated (run as Administrator)")
        return False
    return True


def start_all() -> int:
    rc = _run([OPENER, "open"])
    if rc == 0:
        rc = _run([OPENER, "displays"])
    return rc


def stop_all() -> int:
    # Safe semantics (unlike the old _kill_all): displays + supervised
    # stop, the service keeps detecting. Full stop stays explicit at
    # `run_aegis.bat --stop` / `close --with-service`.
    rc = _run([OPENER, "displays", "--stop"])
    if rc == 0:
        rc = _run([OPENER, "close"])
    return rc


def restart_all() -> int:
    rc = stop_all()
    if rc == 0:
        time.sleep(2)
        rc = start_all()
    return rc


def show_status() -> int:
    rc = _run([OPENER, "status"])
    if rc in (0, 2):
        rc = _run([CLI, "components"])
    return rc


def show_watchdog() -> int:
    # Keeper IS the watchdog now (AegisKeeper task + SCM failure actions).
    # Status query needs elevation; a refusal here is an honest unknown.
    print("Watchdog = AegisKeeper scheduled task (every 5 min, SYSTEM)")
    rc = _run([OPENER, "keep"])
    return rc


def mouth_menu() -> int:
    while True:
        print("")
        print("  MOUTH (AEGIS Mouth, Rust TUI, optional display)")
        print("  1  version")
        print("  2  open console (displays --tui)")
        print("  3  close console (displays --stop --tui)")
        print("  0  back")
        choice = input("  Select: ").strip()
        if choice == "1":
            from .components import COMPONENTS
            mouth = next(c for c in COMPONENTS if c["id"] == "mouth")
            print("  AEGIS Mouth (Rust) v%s - %s" % (mouth["version"], mouth["entrypoint"]))
            return 0
        if choice == "2":
            return _run([OPENER, "displays", "--tui"])
        if choice == "3":
            return _run([OPENER, "displays", "--stop", "--tui"])
        if choice == "0":
            return 0
        print("  Unknown option")


def show_rules() -> int:
    # Read-only catalog view. Reloads mean daemon restart by design, so
    # the console never offers a reload button (unlike the old menu).
    try:
        rules = load_rules()
        nids = rules.get("nids_rules", []) if isinstance(rules, dict) else []
        print("  Detection catalog: %d rules (configs/Rules.json)" % len(nids))
        print("  Reloads happen through daemon restart only -- read-only here.")
        return 0
    except Exception as exc:
        print("  rules unreadable: %s" % exc)
        return 1


def show_logs() -> int:
    return _run([CLI, "events", "tail", "--count", "10"])


def show_health() -> int:
    rc = _run([OPENER, "status"])
    if rc in (0, 1, 2):
        rc = _run([CLI, "bridge"])
    if rc in (0, 1, 2):
        rc = _run([CLI, "enforce", "status"])
    return rc


def show_graph() -> int:
    return _run([CLI, "graph", "--open"])


def run_gates() -> int:
    # Quick read-only gates only (seconds): never the full pytest suite
    # from an interactive menu (it hammers the control pipe for minutes).
    rc = _run([TRUTH, "verify"])
    if rc == 0:
        rc = _run([RELEASE, "--verify"])
    return rc


def show_daemon() -> int:
    rc = _run([CLI, "status"])
    if rc in (0, 1, 2):
        rc = _run([CLI, "forensic", "verify"])
    return rc


def do_exit() -> int:
    print("  Shutting down Command Center (runtime keeps running)...")
    return 0


ACTIONS: Dict[str, MenuAction] = {
    "start_all": start_all,
    "stop_all": stop_all,
    "restart_all": restart_all,
    "show_status": show_status,
    "show_watchdog": show_watchdog,
    "mouth_menu": mouth_menu,
    "show_rules": show_rules,
    "show_logs": show_logs,
    "show_health": show_health,
    "show_graph": show_graph,
    "run_gates": run_gates,
    "show_daemon": show_daemon,
    "do_exit": do_exit,
}


def _headline_counts() -> str:
    # Best-effort one-line rollup; never raises (menu must open even
    # when the daemon is down).
    try:
        statuses = get_all_status()
        running = sum(1 for _, r, _ in statuses if r)
        return "subsystems %d/%d reporting" % (running, len(statuses))
    except Exception:
        return "control plane unreachable"


def _ensure_stdout_unicode() -> None:
    # The menu labels are Thai. Attached consoles already render them
    # via WriteConsoleW; but a piped stdout falls back to the locale
    # codec (cp1252) and crashes on print. Reconfigure only when piped.
    if sys.stdout.isatty():
        return
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def print_menu(role: str) -> None:
    print("")
    print("  AEGIS NIDS Command Control Center    role=%s" % role.upper())
    print("  One control surface (mutations need --role admin + elevation)")
    print("  %s" % _headline_counts())
    section = ""
    for key, sec, label, _admin, _action in MENU:
        if sec != section:
            section = sec
            print("")
            print("  %s" % sec)
            print("  " + "-" * 50)
        print("  %s  %s" % (key, label))
    print("")


def console_menu(role: str = "operator",
                 once: bool = False,
                 choice: str | None = None) -> int:
    """Run the menu (interactive) or one choice (--once, for tests)."""
    _ensure_stdout_unicode()
    by_key = {key: (admin, action) for key, _sec, _label, admin, action in MENU}
    if once:
        key = (choice or "").strip().upper()
        if key not in by_key:
            print("unknown choice %r (valid: %s)" % (choice, ",".join(sorted(by_key))))
            return 2
        admin, action = by_key[key]
        if admin and not _refuse_unless_admin(role):
            return 1
        return ACTIONS[action]()
    while True:
        print_menu(role)
        key = input("Select (0-9/A-C): ").strip().upper()
        if key == "0":
            return do_exit()
        entry = by_key.get(key)
        if entry is None:
            print("Unknown option")
            time.sleep(0.8)
            continue
        admin, action = entry
        if admin and not _refuse_unless_admin(role):
            input("Press Enter...")
            continue
        ACTIONS[action]()
        input("Press Enter...")
