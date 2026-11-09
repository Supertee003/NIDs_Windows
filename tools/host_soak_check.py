"""Evaluate the R-08 soak window against recorded facts, not recollection.

R-08's exit criterion ends with "24h soak clean". A soak that nobody can
evaluate is indistinguishable from no soak, so this tool answers one question:
since the recorded start, have the four services stayed Running, has the daemon
restarted, and has it reported any error?

Usage:
    python tools/host_soak_check.py --start 2026-11-10T02:13:00
    python tools/host_soak_check.py --start ... --hours 24 --json out.json

Exit codes:
    0  complete and clean
    2  soak still in progress
    3  failed (restart, stopped service, or daemon error)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import subprocess
import sys

SERVICES = ("AegisNids", "AegisAggregator", "AegisWfp", "AegisMinifilter")


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


def daemon_status() -> dict:
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
        from aegisctl.client import AegisClient  # noqa: PLC0415

        out = AegisClient().send("status")
        body = out.get("data") or out
        if isinstance(body, str):
            body = json.loads(body)
        return body if isinstance(body, dict) else {}
    except Exception as exc:  # noqa: BLE001 - a dead daemon is a result, not a crash
        return {"error": f"{type(exc).__name__}: {exc}"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--start",
        required=True,
        help="soak start as ISO-8601 local time, or 'auto' to derive it from the daemon's uptime",
    )
    parser.add_argument("--hours", type=float, default=24.0, help="required clean duration")
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
    uptime_ms = status.get("uptime_ms")
    uptime_h = (uptime_ms / 3_600_000) if isinstance(uptime_ms, (int, float)) else None

    problems: list[str] = []
    for name in args.expect:
        if states.get(name) != "RUNNING":
            problems.append(f"{name} is {states.get(name, 'MISSING')}")
    if "error" in status:
        problems.append(f"daemon unreachable: {status['error']}")
    else:
        if uptime_h is not None and uptime_h + 0.05 < elapsed_h:
            problems.append(
                f"daemon uptime {uptime_h:.2f}h is shorter than the soak {elapsed_h:.2f}h "
                "(process restarted mid-soak)"
            )

    complete = elapsed_h >= args.hours
    verdict = "FAIL" if problems else ("PASS" if complete else "IN_PROGRESS")

    report = {
        "verdict": verdict,
        "soak_start": started.isoformat(),
        "checked_at": now.isoformat(timespec="seconds"),
        "elapsed_hours": round(elapsed_h, 2),
        "required_hours": args.hours,
        "services": states,
        "daemon_uptime_hours": round(uptime_h, 2) if uptime_h is not None else None,
        "daemon_state": status.get("state") if isinstance(status, dict) else None,
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
