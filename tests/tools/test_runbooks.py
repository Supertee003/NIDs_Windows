"""EVT-166: runbooks must be executable, not pseudocode.

The RB series described Zig APIs, dead subsystems, and stale paths
(`config/`, aggregator :9200, anomalous.json, aegis.ps1,
--no-dashboard). After the rewrite pass, every runbook step must name
something real. Pins:
  - no stale markers anywhere under docs/runbooks/;
  - RB-006 (the health baseline) references the live command set and
    the exit-code contract;
  - every RB file keeps Objective/Steps/Verification/Rollback bones.

Content quality beyond that is review, not test.
"""
from __future__ import annotations

from pathlib import Path

RB = Path(__file__).resolve().parents[2] / "docs" / "runbooks"

STALE_MARKERS = (
    "aggregator :9200",
    "aggregator (:9200)",
    ":9200",
    "anomalous.json",
    "aegis.ps1",
    "--no-dashboard",
    "config/Rules.json",
    "core/pep_enforcement_proof.zig",
    "core/audit_trail_proof.zig",
)


def _files():
    return sorted(RB.glob("RB-*.md"))


def _has(text: str, *alts: str) -> bool:
    return any(a in text for a in alts)


def test_runbooks_have_bones():
    # Lab proofs (host/VM split) use Purpose/Acceptance/Safety instead of
    # the standard four; both shapes are executable, so both pass.
    files = _files()
    assert len(files) >= 17, len(files)
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert _has(text, "## Objective", "## Purpose"), (path.name, "goal")
        assert _has(text, "## Steps", "## Acceptance", "## Checklist"), (path.name, "procedure")
        assert _has(text, "## Verification", "## Acceptance"), (path.name, "outcome")
        assert _has(text, "## Rollback", "## Safety contract"), (path.name, "backout")


def test_runbook_index_matches_files():
    # Renames (RB-007 double-numbering, EVT-167) must update the index,
    # or the catalog silently rots.
    import re
    index = (RB / "README.md").read_text(encoding="utf-8")
    listed = set(re.findall(r"\[RB-(\d+)\]\(", index))
    present = {p.name[3:6] for p in _files()}
    assert listed == present, (listed ^ present)
    numbers = sorted(p.name[3:6] for p in _files())
    assert len(numbers) == len(set(numbers)), "duplicate RB numbers"


def test_runbooks_carry_no_stale_markers():
    bad = []
    for path in _files():
        text = path.read_text(encoding="utf-8")
        for marker in STALE_MARKERS:
            if marker in text:
                bad.append((path.name, marker))
    assert not bad, bad


def test_rb006_names_the_live_contract():
    text = (RB / "RB-006-subsystem-health-check.md").read_text(encoding="utf-8")
    for token in ("aegis_open.py status", "aegisctl.py readiness",
                  "aegisctl.py components", "aegisctl.py bridge",
                  "**2**", "unknown"):
        assert token in text, token
