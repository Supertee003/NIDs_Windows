"""Dead-service watchdog (GAP-016).

Detection only — this script NEVER spawns processes, restarts services,
or touches host state (T16: no-spawn holds for all repo Python; restart
belongs to the Service Control Manager via `sc failure`, configured
separately). It exits 0 when the daemon reports RUNNING through the
control pipe and 1 otherwise, appending one line per failure to a
scratch log outside the repo tree. Run it from Task Scheduler every few
minutes as SYSTEM; alerting reads the exit code / task history.

Scheduled-task setup (elevated, once):
  schtasks /create /tn AegisWatchdog /tr "python D:\\NIDs_Windows\\tools\\service_watchdog.py" /sc minute /mo 5 /ru SYSTEM /rl highest /f
SCM crash recovery (elevated, once — restarts the service 60s after a crash):
  sc failure AegisNids reset= 86400 actions= restart/60000/restart/60000/restart/60000
"""
from __future__ import annotations

import datetime
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

WATCHDOG_LOG = Path(r"C:\Temp\aegis_watchdog.log")


def _line(text: str) -> None:
    try:
        with WATCHDOG_LOG.open("a", encoding="utf-8") as handle:
            handle.write("%s %s\n" % (datetime.datetime.now().isoformat(timespec="seconds"), text))
    except OSError:
        pass


def check() -> int:
    """Return 0 when the daemon is RUNNING, 1 otherwise (and log why)."""
    try:
        from aegisctl.api.control_api import query_control
    except Exception as exc:  # pragma: no cover - import environment
        _line("control_api_unavailable: %s" % exc)
        return 1
    try:
        response = query_control("system.health")
    except Exception as exc:
        _line("control_query_exception: %s" % exc)
        return 1
    if not response:
        _line("daemon_unreachable")
        return 1
    state = response.get("state", "UNKNOWN")
    if state != "RUNNING":
        _line("daemon_not_running state=%s degraded=%s" % (state, response.get("degraded")))
        return 1
    return 0


def main() -> int:
    return check()


if __name__ == "__main__":
    raise SystemExit(main())
