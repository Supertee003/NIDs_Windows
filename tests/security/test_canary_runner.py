"""Gate-E canary runner contracts (behavioral).

`canary` is read-only detection-readiness verification: it loads
configs/canary_tests.json, checks each expected rule against
configs/Rules.json (+ live engine count when the daemon answers), and
prints a JSON verdict. It never touches enforcement, the engine, or
local enforcement bookkeeping (blocked_ips.json/quarantine.json).

Runs the real CLI as a subprocess against the real tree. E2.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CLI = REPO / "tools" / "aegisctl.py"
LOGS = REPO / "logs"


def run(*argv: str):
    return subprocess.run(
        [sys.executable, str(CLI), *argv],
        capture_output=True, text=True, timeout=60, cwd=REPO,
    )


def snapshot():
    return {
        p.name: (p.read_bytes() if p.exists() else None)
        for p in (LOGS / "blocked_ips.json", LOGS / "quarantine.json")
    }


def test_canary_status_reports_definitions_and_file():
    proc = run("canary", "status")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["available"] is True
    assert payload["definitions"] == 10
    assert payload["rules_in_file"] == 22
    assert payload["definitions_error"] is None
    assert payload["rules_error"] is None


def test_canary_run_single_passing_test_is_zero():
    proc = run("canary", "run", "--test", "sqli_bypass")
    assert proc.returncode == 0, proc.stdout
    payload = json.loads(proc.stdout)
    assert payload["passed"] == 1 and payload["failed"] == 0


def test_canary_run_unknown_test_is_usage_error():
    proc = run("canary", "run", "--test", "no-such-canary")
    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["available"] is False
    assert payload["reason"] == "unknown_canary_test"


def test_canary_report_round_trips_last_run():
    assert run("canary", "run", "--test", "sqli_bypass").returncode == 0
    proc = run("canary", "report")
    assert proc.returncode == 0, proc.stdout
    payload = json.loads(proc.stdout)
    assert payload["available"] is True
    assert payload["passed"] >= 1


def test_canary_run_writes_no_enforcement_state():
    before = snapshot()
    run("canary", "run", "--test", "sqli_bypass")
    assert snapshot() == before, "canary must not touch enforcement bookkeeping"


def test_canary_reports_definition_drift_honestly():
    """The two known stale expectations must surface as severity_mismatch
    (expected vs actual named), never as a pass and never as a crash."""
    proc = run("canary", "run")
    assert proc.returncode in (0, 1), proc.stdout
    payload = json.loads(proc.stdout)
    by_name = {d["name"]: d for d in payload["details"]}
    for name in ("rfi_basic", "data_exfil"):
        assert by_name[name]["passed"] is False
        assert by_name[name]["reason"] == "severity_mismatch"
        assert "expected" in by_name[name] and "actual" in by_name[name]
