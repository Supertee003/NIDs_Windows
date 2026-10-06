"""CI-GATE-107: CI enforces truth stamps and pins its supply chain.

Failure mode pinned: the pre-commit checklist demands `truth.py
verify`, but CI never ran it (a stale-map commit passed the pipeline),
and the Trivy step floated on `@master` (a moving supply-chain ref).
Contract:

  AC1. The python-tests job runs `truth.py verify` after the
       provenance gate (fail-fast on stale maps, same as pre-commit).
  AC2. No workflow step floats on `@master`/`@main`; the Trivy action
       is pinned to a released tag, and its non-blocking status is a
       documented decision (needs a triage SLA to enforce), not drift.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _workflow() -> str:
    return CI.read_text(encoding="utf-8")


def test_truth_verify_gate_runs_in_ci():
    text = _workflow()
    assert "python tools/truth.py verify" in text
    assert text.index("release_engineering.py --verify") < text.index("python tools/truth.py verify")


def test_no_floating_action_refs():
    text = _workflow()
    assert "trivy-action@master" not in text
    # Only `uses:` lines may carry refs; comments mention @master to
    # explain the pin and must not trip the check.
    uses = [line for line in text.splitlines() if "uses:" in line]
    assert uses, "expected at least one uses: step"
    for line in uses:
        assert "@master" not in line and "@main" not in line, line.strip()


def test_trivy_pin_is_a_release_tag():
    import re

    text = _workflow()
    assert re.search(r"trivy-action@0\.36\.0", text), "Trivy must stay pinned to a verified release"
    assert "exit-code: 0" in text
