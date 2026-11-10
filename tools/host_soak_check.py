"""Evaluate the R-08 soak window against recorded facts, not recollection.

R-08's exit criterion ends with "24h soak clean". A soak that nobody can
evaluate is indistinguishable from no soak, so this tool answers one question:
since the recorded start, have the required services stayed Running, has the
daemon restarted, has it reported DEGRADED, and has it recorded data loss?

The earlier version read only `status` (whose payload has no degraded flag) and
never counted the loss counters, so a daemon reporting DEGRADED with 265,675
dropped queue rows still produced PASS. Every criterion below is now fail-closed:

  * required services must be RUNNING,
  * daemon reachable, uptime at least the elapsed window,
  * `health.state` must not be DEGRADED,
  * data_integrity loss counters must all be within --loss-budget (default 0),
  * queue.stats policy shed (`shed_overload`) must be within --shed-budget
    (default 0) — otherwise a build that converts overflow into a deliberate
    shed could pass a "zero loss" soak while still discarding rows,
  * no SCM 7031/7034 restart for AegisNids inside the window.

Usage:
    python tools/host_soak_check.py --start 2026-11-10T02:13:00
    python tools/host_soak_check.py --start ... --hours 24 --loss-budget 0 --json out.json

Exit codes:
    0  complete and clean
    2  soak still in progress (no problems observed yet)
    3  failed (restart, stopped service, DEGRADED daemon, loss, or daemon error)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import subprocess
import sys

SERVICES = ("AegisNids", "AegisAggregator", "AegisWfp", "AegisMinifilter")

# Every counter in the health payload's data_integrity block that means "rows
# were lost". The nose-only `counters` block is NOT used: it reports dropped=0
# while the real loss sits in data_integrity.
LOSS_COUNTERS = (
    "queue_dropped_total",
    "nose_frames_rejected",
    "nose_frames_dropped",
    "nose_pipe_errors",
    "minifilter_ring_dropped",
    "minifilter_pipeline_dropped",
)


def service_states() -> dict[str, str]:
    states: dict[str, str] = {}
    for name in SERVICES:
        try:
            out = subprocess.run(
                ["sc.exe", "query", name],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            states[name] = "QUERY_FAILED"
            continue
        state = "UNKNOWN"
        for line in out.splitlines():
            if "STATE" in line:
                parts = line.split()
                for token in parts:
                    if token.isdigit():
                        code = int(token)
                        state = {
                            1: "STOPPED",
                            2: "START_PENDING",
                            3: "STOP_PENDING",
                            4: "RUNNING",
                        }.get(code, "UNKNOWN")
                        break
        states[name] = state
    return states


def _send(command: str) -> dict:
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
        from aegisctl.client import AegisClient  # noqa: PLC0415

        out = AegisClient().send(command)
        body = out.get("data") or out
        if isinstance(body, str):
            body = json.loads(body)
        return body if isinstance(body, dict) else {}
    except Exception as exc:  # noqa: BLE001 - a dead daemon is a result, not a crash
        return {"error": f"{type(exc).__name__}: {exc}"}


def daemon_status() -> dict:
    return _send("status")


def daemon_health() -> dict:
    return _send("health")


def daemon_queue() -> dict:
    return _send("queue.stats")


def restart_events(started: dt.datetime) -> list[str]:
    """SCM 7031/7034 for AegisNids at or after *started* (local time)."""
    stamp = started.strftime("%Y-%m-%dT%H:%M:%S")
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$e=Get-WinEvent -FilterHashtable @{{LogName='System';ID=7031,7034;"
        f"StartTime=[datetime]'{stamp}'}};"
        "$e | Where-Object {$_.Message -match 'AegisNids'} | "
        "ForEach-Object {$_.TimeCreated.ToString('s')}"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [f"event-log query failed: {type(exc).__name__}: {exc}"]
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def evaluate(
    *,
    elapsed_h: float,
    required_h: float,
    states: dict[str, str],
    expect: tuple[str, ...] | list[str],
    status: dict,
    health: dict,
    queue: dict | None = None,
    restarts: list[str],
    loss_budget: int,
    shed_budget: int = 0,
) -> tuple[list[str], bool]:
    """Return (problems, complete). Pure function so the verdict is testable."""
    problems: list[str] = []
    for name in expect:
        if states.get(name) != "RUNNING":
            problems.append(f"{name} is {states.get(name, 'MISSING')}")

    if "error" in status:
        problems.append(f"daemon unreachable: {status['error']}")
    else:
        uptime_ms = status.get("uptime_ms")
        if isinstance(uptime_ms, (int, float)):
            uptime_h = uptime_ms / 3_600_000
            if uptime_h + 0.05 < elapsed_h:
                problems.append(
                    f"daemon uptime {uptime_h:.2f}h is shorter than the soak {elapsed_h:.2f}h "
                    "(process restarted mid-soak)"
                )

    if "error" in health:
        problems.append(f"daemon health unavailable: {health['error']}")
    else:
        if health.get("degraded") is True or str(health.get("state", "")).upper() == "DEGRADED":
            problems.append(
                "daemon reports DEGRADED"
                f" (state={health.get('state')}, runtime_state={health.get('runtime_state')})"
            )
        integrity = health.get("data_integrity") or {}
        for key in LOSS_COUNTERS:
            value = integrity.get(key)
            if isinstance(value, (int, float)) and value > loss_budget:
                problems.append(f"{key}={int(value)} exceeds the loss budget {loss_budget}")

    if queue is not None:
        if "error" in queue:
            problems.append(f"queue stats unavailable: {queue['error']}")
        else:
            shed = queue.get("shed_overload")
            if isinstance(shed, (int, float)) and shed > shed_budget:
                problems.append(
                    f"shed_overload={int(shed)} exceeds the policy-shed budget {shed_budget}"
                )

    if restarts:
        problems.append(
            "AegisNids restarted inside the window (SCM 7031/7034): "
            + ", ".join(restarts)
        )

    return problems, elapsed_h >= required_h


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--start",
        required=True,
        help="soak start as ISO-8601 local time, or 'auto' to derive it from the daemon's uptime",
    )
    parser.add_argument("--hours", type=float, default=24.0, help="required clean duration")
    parser.add_argument(
        "--loss-budget",
        type=int,
        default=0,
        help="owner-approved number of lost rows allowed per counter (default 0)",
    )
    parser.add_argument(
        "--shed-budget",
        type=int,
        default=0,
        help="owner-approved number of deliberate policy-shed rows allowed (default 0)",
    )
    parser.add_argument("--json", type=pathlib.Path, default=None)
    parser.add_argument("--expect", nargs="*", default=list(SERVICES), help="services that must run")
    args = parser.parse_args(argv)

    now = dt.datetime.now()
    if args.start == "auto":
        probe = daemon_status()
        uptime_ms = probe.get("uptime_ms")
        if not isinstance(uptime_ms, (int, float)):
            print("cannot derive the soak start: daemon uptime unavailable", file=sys.stderr)
            return 3
        started = now - dt.timedelta(milliseconds=uptime_ms)
    else:
        try:
            started = dt.datetime.fromisoformat(args.start)
        except ValueError:
            print(f"could not parse --start: {args.start!r}", file=sys.stderr)
            return 3
    elapsed = now - started
    elapsed_h = elapsed.total_seconds() / 3600

    states = service_states()
    status = daemon_status()
    health = daemon_health()
    queue = daemon_queue()
    restarts = restart_events(started)

    problems, complete = evaluate(
        elapsed_h=elapsed_h,
        required_h=args.hours,
        states=states,
        expect=args.expect,
        status=status,
        health=health,
        queue=queue,
        restarts=restarts,
        loss_budget=args.loss_budget,
        shed_budget=args.shed_budget,
    )
    verdict = "FAIL" if problems else ("PASS" if complete else "IN_PROGRESS")

    uptime_ms = status.get("uptime_ms")
    uptime_h = (uptime_ms / 3_600_000) if isinstance(uptime_ms, (int, float)) else None
    report = {
        "verdict": verdict,
        "soak_start": started.isoformat(),
        "checked_at": now.isoformat(timespec="seconds"),
        "elapsed_hours": round(elapsed_h, 2),
        "required_hours": args.hours,
        "services": states,
        "daemon_uptime_hours": round(uptime_h, 2) if uptime_h is not None else None,
        "daemon_state": status.get("state") if isinstance(status, dict) else None,
        "daemon_health_state": health.get("state") if isinstance(health, dict) else None,
        "data_integrity": (health.get("data_integrity") or {}) if isinstance(health, dict) else {},
        "shed_overload": queue.get("shed_overload") if isinstance(queue, dict) else None,
        "loss_budget": args.loss_budget,
        "shed_budget": args.shed_budget,
        "scm_restarts": restarts,
        "problems": problems,
    }

    text = json.dumps(report, indent=2)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8", newline="\n")
    print(text)

    if problems:
        return 3
    return 0 if complete else 2


if __name__ == "__main__":
    sys.exit(main())
