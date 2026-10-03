"""NEG-002: CLI mutations never claim host effect (behavioral).

Constitution 9 + Doc 08 section 5: only ENFORCED + host_effect_confirmed
may render as confirmed blocking. The canonical CLI therefore refuses
block/quarantine/enforce mutations offline (exit != 0, no local writes,
no BLOCKED/QUARANTINED claims) and keeps list/status reads working.

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


def test_block_add_is_refused_without_host_effect():
    before = snapshot()
    proc = run("block", "add", "--ip", "203.0.113.9", "--reason", "neg-test")
    assert proc.returncode != 0, "block add must not succeed offline"
    assert "BLOCKED" not in proc.stdout, "CLI must never print BLOCKED without a receipt"
    assert snapshot() == before, "block add must not write local bookkeeping"


def test_quarantine_add_is_refused_without_host_effect():
    before = snapshot()
    proc = run("quarantine", "add", "--ip", "203.0.113.9", "--reason", "neg-test")
    assert proc.returncode != 0, "quarantine add must not succeed offline"
    assert "QUARANTINED" not in proc.stdout
    assert snapshot() == before, "quarantine add must not write local bookkeeping"


def test_enforce_mutation_is_refused():
    proc = run("enforce", "enable")
    assert proc.returncode != 0, "enforce enable must not flip posture offline"


def test_enforce_two_person_and_approve_are_honest():
    """Project 3 (T3-TWOP-023): the two-person CLI edge routes to the daemon
    (0 live) and answers honest-offline (3 + available:false, never an
    approval claim) when the Control Center is unreachable."""
    for argv in (("enforce", "two-person", "on"),
                 ("enforce", "two-person", "off"),
                 ("enforce", "approve", "991")):
        proc = run(*argv)
        assert proc.returncode in (0, 3), f"{argv}: {proc.stdout}"
        payload = json.loads(proc.stdout)
        if proc.returncode == 3:
            assert payload.get("available") is False
            assert payload.get("reason"), "offline answer must name the reason"
            assert "approved" not in payload, "offline answer must not claim approval"


def test_enforce_approve_rejects_non_positive_request_id_locally():
    for argv in (("enforce", "approve", "0"), ("enforce", "approve", "-5")):
        proc = run(*argv)
        assert proc.returncode == 2, f"{argv} must fail local validation"
        payload = json.loads(proc.stdout)
        assert payload.get("available") is False
        assert "approved" not in payload


def test_read_paths_still_work():
    assert run("block", "list").returncode == 0
    assert run("quarantine", "list").returncode == 0
    status = run("enforce", "status")
    # Exit-code contract (AEGIS_Operator_UX_Specification, Unified CLI):
    # 0 = Control Center answered, 3 = Control Center unavailable. Offline is
    # an honest answer, never a host-effect claim.
    assert status.returncode in (0, 3), status.stdout
    payload = json.loads(status.stdout)
    if status.returncode == 3:
        assert payload.get("available") is False
        assert payload.get("reason"), "offline status must name the reason"
    assert run("federation").returncode in (0, 3)  # 0 live daemon, 3 offline


def test_source_contains_no_effect_claims():
    """Static lock: the effect-claim strings must not exist in the CLI."""
    src = CLI.read_text(encoding="utf-8")
    for lie in ('already BLOCKED', 'already QUARANTINED', '"BLOCKED"', '"QUARANTINED"',
                'UNBLOCKED', 'removed from quarantine', 'Policy pushed'):
        assert lie not in src, f"effect-claim string present: {lie}"
