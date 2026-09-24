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


def test_read_paths_still_work():
    assert run("block", "list").returncode == 0
    assert run("quarantine", "list").returncode == 0
    assert run("enforce", "status").returncode == 0
    assert run("federation").returncode in (0, 3)  # 0 live daemon, 3 offline


def test_source_contains_no_effect_claims():
    """Static lock: the effect-claim strings must not exist in the CLI."""
    src = CLI.read_text(encoding="utf-8")
    for lie in ('already BLOCKED', 'already QUARANTINED', '"BLOCKED"', '"QUARANTINED"',
                'UNBLOCKED', 'removed from quarantine', 'Policy pushed'):
        assert lie not in src, f"effect-claim string present: {lie}"
