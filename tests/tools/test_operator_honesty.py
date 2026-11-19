"""OPERATOR-001: operator surfaces must not advertise capability they lack.

The plan asked for push notifier transport, rule mutation and signed policy
promotion. Current source deliberately keeps those fail-closed / retired to
preserve the detection-only authority boundary. This module pins that the
help text and docs tell the truth instead of promising an apply step.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CLI = REPO / "tools" / "aegisctl.py"


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8", errors="ignore")


def test_policy_mutation_verbs_stay_registered_but_help_says_unavailable():
    # Registered on purpose: tests/runtime/test_gate_e.py exercises the
    # fail-closed path through them. Removing the verbs would hide the gate.
    source = CLI.read_text(encoding="utf-8")
    for verb in ("reload", "enable", "disable"):
        assert f'add_parser("{verb}", help=_unavail)' in source
    assert "UNAVAILABLE (fail-closed, exit 4)" in source

    out = subprocess.run(
        [sys.executable, str(CLI), "policy", "--help"],
        cwd=REPO, capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 0, out.stderr
    assert "UNAVAILABLE" in out.stdout
    assert "disabled_rules.json" in out.stdout
    assert "rules reload" in out.stdout


def test_notifier_stays_retired_no_pushed_transport_wired():
    # No egress, no secrets, no managed runner — detection-only.
    source = _read("scripts/aegis_notifier.py")
    assert "RETIRED (EVT-152)" in source
    matrix = _read("docs/runtime/COMPONENT_MATRIX.md")
    assert "RETIRED (EVT-152" in matrix
    assert "No external alert delivery" in matrix
    # No new runner/manifest reference may appear.
    for rel in ("scripts/aegis_open.py", "scripts/run_aegis.bat", "runtime_manifest.json"):
        assert "notifier" not in _read(rel).lower()


def test_docs_do_not_claim_signed_ir_promotion_or_operate_role():
    map_doc = _read("docs/OPERATOR_COMMAND_MAP.md")
    assert "`.privileged` role" in map_doc
    assert "(.operate role)" not in map_doc

    ir_doc = _read("docs/runbooks/RB-011-policy-ir-mirror-workflow.md")
    assert "READ-ONLY signed-envelope report" in ir_doc
    assert "never replaces the runtime PolicySet" in ir_doc
    assert "NOT_IMPLEMENTED" not in ir_doc
