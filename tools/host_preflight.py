"""Post-install host preflight: the E5 gate for INSTALLER-BOOT-MODEL-001.

`RC-FINAL` §3 item 5 and `INSTALLER-BOOT-MODEL-001` end at the same wall: the
installers now ship demand-start services, an `AegisBootSequence` task and
`AEGIS_LOSS_BUDGET`, but nobody has run a fresh install, rebooted, and checked
what actually came up. That check is mechanical, so it should not depend on a
person remembering eight commands — and it must not be a checklist someone can
tick from memory.

This tool reads the host and answers one question: did this machine come up the
way the installer claims it will?

  * `AegisNids` is DEMAND_START (AUTO_START reproduces the 2026-11-11 boot
    failure: SCM starts the daemon before the demand-start drivers, the ring
    fills with no reader, and the daemon is degraded from its first second),
  * the service carries `AEGIS_LOSS_BUDGET` with the expected value,
  * `AegisBootSequence` exists, is enabled, runs as SYSTEM, last exited 0, and
    points at the loader *inside the install directory* (a lab host hand-fixed
    with an `admin-evidence` script is not an installed host),
  * `AegisWfp` and `AegisMinifilter` are RUNNING,
  * the daemon reports RUNNING, not degraded, with the same loss budget, and
  * `minifilter_ring_dropped` is 0 — the ring is drained by a reader that was
    running before the minifilter started.

Every check is fail-closed: an unreadable value is a failure, never a pass.

Usage:
    python tools/host_preflight.py --loss-budget 3500
    python tools/host_preflight.py --loss-budget 3500 --json admin-evidence/preflight.json

Exit codes:
    0  every check passed
    3  at least one check failed (the report names it)
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

DEFAULT_INSTALL_DIR = r"C:\Program Files\AEGIS NIDS"
TASK_NAME = "AegisBootSequence"
SERVICE = "AegisNids"
EXPECTED_DRIVERS = ("AegisWfp", "AegisMinifilter")
LOADER_NAME = "boot-sequence.ps1"


# ── collectors ─────────────────────────────────────────────────────────────

def _run(argv: list[str], timeout: int = 30) -> str:
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"ERROR {type(exc).__name__}: {exc}"
    return proc.stdout + proc.stderr


def service_config() -> dict:
    """`sc qc` for AegisNids: start type and binary path."""
    out = _run(["sc.exe", "qc", SERVICE])
    start = re.search(r"START_TYPE\s*:\s*\d+\s+(\w+)", out)
    binary = re.search(r"BINARY_PATH_NAME\s*:\s*(.+)", out)
    start_name = re.search(r"SERVICE_START_NAME\s*:\s*(\S+)", out)
    return {
        "start_type": start.group(1).strip() if start else None,
        "binary": binary.group(1).strip() if binary else None,
        "start_name": start_name.group(1).strip() if start_name else None,
        "raw_error": None if start else out.strip()[:400],
    }


def service_environment() -> dict:
    """The service Environment REG_MULTI_SZ, as the SCM will pass it."""
    out = _run(
        [
            "reg",
            "query",
            rf"HKLM\SYSTEM\CurrentControlSet\Services\{SERVICE}",
            "/v",
            "Environment",
        ]
    )
    match = re.search(r"Environment\s+REG_MULTI_SZ\s+(.+)", out)
    raw = match.group(1).strip() if match else None
    budget = None
    if raw:
        for token in raw.split():
            if token.upper().startswith("AEGIS_LOSS_BUDGET="):
                value = token.split("=", 1)[1].strip()
                budget = int(value) if value.lstrip("-").isdigit() else None
    return {"raw": raw, "loss_budget": budget, "raw_error": None if match else out.strip()[:400]}


def boot_task() -> dict:
    out = _run(["schtasks", "/query", "/tn", TASK_NAME, "/fo", "LIST", "/v"], timeout=60)
    if "cannot find" in out.lower() or "ERROR" in out:
        return {
            "exists": False,
            "state": None,
            "run_as": None,
            "last_result": None,
            "task_to_run": None,
            "raw_error": out.strip()[:400],
        }

    def field(name: str) -> str | None:
        found = re.search(rf"^{re.escape(name)}\s*:\s*(.*)$", out, re.MULTILINE)
        return found.group(1).strip() if found else None

    last = field("Last Result")
    last_result = int(last) if last and last.lstrip("-").isdigit() else None
    return {
        "exists": True,
        "state": field("Scheduled Task State"),
        "run_as": field("Run As User"),
        "last_result": last_result,
        "task_to_run": field("Task To Run"),
        "raw_error": None,
    }


def states(names: tuple[str, ...]) -> dict[str, str]:
    found: dict[str, str] = {}
    for name in names:
        out = _run(["sc.exe", "query", name])
        state = "UNKNOWN"
        for line in out.splitlines():
            if "STATE" in line:
                for token in line.split():
                    if token.isdigit():
                        state = {
                            1: "STOPPED",
                            2: "START_PENDING",
                            3: "STOP_PENDING",
                            4: "RUNNING",
                        }.get(int(token), "UNKNOWN")
                        break
        found[name] = state
    return found


def daemon_health() -> dict:
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
        from aegisctl.client import AegisClient  # noqa: PLC0415

        out = AegisClient().send("health")
        body = out.get("data") or out
        if isinstance(body, str):
            body = json.loads(body)
        return body if isinstance(body, dict) else {}
    except Exception as exc:  # noqa: BLE001 - an unreachable daemon is a result
        return {"error": f"{type(exc).__name__}: {exc}"}


def daemon_status() -> dict:
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
        from aegisctl.client import AegisClient  # noqa: PLC0415

        out = AegisClient().send("status")
        body = out.get("data") or out
        if isinstance(body, str):
            body = json.loads(body)
        return body if isinstance(body, dict) else {}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}


# ── verdict ────────────────────────────────────────────────────────────────

def evaluate(
    facts: dict,
    *,
    loss_budget: int,
    install_dir: str = DEFAULT_INSTALL_DIR,
    min_uptime_min: float = 0.0,
) -> list[dict]:
    """Return one record per check: {id, ok, detail}. Pure, so it is testable."""
    checks: list[dict] = []

    def add(check_id: str, ok: bool, detail: str) -> None:
        checks.append({"id": check_id, "ok": bool(ok), "detail": detail})

    service = facts.get("service") or {}
    start_type = service.get("start_type")
    add(
        "service_start_type",
        start_type == "DEMAND_START",
        f"{SERVICE} START_TYPE is {start_type or 'unreadable'}"
        + ("" if start_type == "DEMAND_START" else
           " — AUTO_START starts the daemon before its drivers (2026-11-11 boot failure)"),
    )

    env = facts.get("env") or {}
    env_budget = env.get("loss_budget")
    add(
        "service_loss_budget",
        env_budget == loss_budget,
        f"AEGIS_LOSS_BUDGET is {env_budget if env_budget is not None else 'unreadable'}"
        f" (expected {loss_budget})",
    )

    task = facts.get("task") or {}
    add(
        "boot_task_present",
        bool(task.get("exists")) and task.get("state") == "Enabled",
        f"{TASK_NAME} exists={task.get('exists')} state={task.get('state')}",
    )
    add(
        "boot_task_system",
        task.get("run_as") == "SYSTEM",
        f"{TASK_NAME} runs as {task.get('run_as') or 'unreadable'}",
    )
    add(
        "boot_task_last_result",
        task.get("last_result") == 0,
        f"{TASK_NAME} last result {task.get('last_result')}"
        + ("" if task.get("last_result") == 0 else " (non-zero: the loader failed)"),
    )

    command = (task.get("task_to_run") or "").replace('"', "")
    loader_ok = bool(command) and LOADER_NAME in command and install_dir.lower() in command.lower()
    add(
        "boot_task_loader_installed",
        loader_ok,
        f"loader is {command or 'unreadable'}"
        + ("" if loader_ok else f" — expected {LOADER_NAME} under {install_dir}"),
    )

    services = facts.get("services") or {}
    for name in EXPECTED_DRIVERS:
        add(
            f"driver_{name}",
            services.get(name) == "RUNNING",
            f"{name} is {services.get(name, 'MISSING')}",
        )

    health = facts.get("health") or {}
    if "error" in health:
        add("daemon_health", False, f"daemon health unavailable: {health['error']}")
    else:
        state = str(health.get("state", "")).upper()
        degraded = health.get("degraded") is True or state == "DEGRADED"
        add("daemon_health", state == "RUNNING" and not degraded, f"state={state} degraded={degraded}")
        integrity = health.get("data_integrity") or {}
        add(
            "daemon_loss_budget",
            integrity.get("loss_budget") == loss_budget,
            f"health loss_budget is {integrity.get('loss_budget')} (expected {loss_budget})",
        )
        ring = integrity.get("minifilter_ring_dropped")
        add(
            "minifilter_ring_clean",
            ring == 0,
            f"minifilter_ring_dropped is {ring if ring is not None else 'unreadable'}",
        )

    status = facts.get("status") or {}
    uptime_ms = status.get("uptime_ms")
    if not isinstance(uptime_ms, (int, float)):
        add("daemon_uptime", False, "daemon uptime unavailable")
    else:
        uptime_min = uptime_ms / 60_000
        add(
            "daemon_uptime",
            uptime_min >= min_uptime_min,
            f"daemon uptime {uptime_min:.1f} min (minimum {min_uptime_min:.1f})",
        )

    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--loss-budget", type=int, default=3500)
    parser.add_argument("--install-dir", default=DEFAULT_INSTALL_DIR)
    parser.add_argument(
        "--min-uptime-min",
        type=float,
        default=0.0,
        help="require the daemon to have been up at least this long (boot-order proof)",
    )
    parser.add_argument("--json", type=pathlib.Path, default=None)
    args = parser.parse_args(argv)

    facts = {
        "service": service_config(),
        "env": service_environment(),
        "task": boot_task(),
        "services": states(EXPECTED_DRIVERS + (SERVICE,)),
        "health": daemon_health(),
        "status": daemon_status(),
    }
    checks = evaluate(
        facts,
        loss_budget=args.loss_budget,
        install_dir=args.install_dir,
        min_uptime_min=args.min_uptime_min,
    )
    failed = [c for c in checks if not c["ok"]]
    report = {
        "verdict": "PASS" if not failed else "FAIL",
        "checked_at_facts": facts,
        "loss_budget": args.loss_budget,
        "install_dir": args.install_dir,
        "checks": checks,
        "failed": [c["id"] for c in failed],
    }
    text = json.dumps(report, indent=2)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text + "\n", encoding="utf-8", newline="\n")
    print(text)
    return 0 if not failed else 3


if __name__ == "__main__":
    sys.exit(main())
