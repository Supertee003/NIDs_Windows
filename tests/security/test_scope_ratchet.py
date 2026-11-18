"""R-03 ratchet: evidence debt may shrink, never grow.

Every tracked file in a product unit must be named by some evidence entry.
Today that is false for 539 of 705 files (measured 2026-11-09). This test does
not pretend the debt is gone: it pins the exact set and fails the moment the
set changes, in either direction.

Growth fails because a new product file with no evidence is the beginning of
silent scope. Shrink also fails, because the baseline must be trimmed in the
same patch that names a file, so the number on record is always the real one.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import evidence_debt  # noqa: E402


def test_baseline_exists_and_is_well_formed() -> None:
    data = json.loads(evidence_debt.BASELINE.read_text(encoding="utf-8"))
    assert data["count"] == len(data["unnamed"]), (
        "baseline count disagrees with its own list; regenerate with "
        "`python tools/evidence_debt.py --write`"
    )
    assert len(data["unnamed"]) == len(set(data["unnamed"])), (
        "baseline contains duplicate paths"
    )


def test_product_evidence_debt_has_not_grown() -> None:
    baseline = json.loads(evidence_debt.BASELINE.read_text(encoding="utf-8"))
    pinned = set(baseline["unnamed"])

    current = evidence_debt.compute()
    unnamed = set(current["unnamed"])

    added = sorted(unnamed - pinned)
    assert not added, (
        "new product files with no evidence entry:\n  "
        + "\n  ".join(added[:20])
        + f"\n({len(added)} new; name them in EVIDENCE_INDEX.json or they do "
        "not belong in a product unit)"
    )

    removed = sorted(pinned - unnamed)
    assert not removed, (
        "these files are now named by evidence, so the baseline is stale:\n  "
        + "\n  ".join(removed[:20])
        + f"\n({len(removed)} closed) Trim them with "
        "`python tools/evidence_debt.py --write` in the same patch."
    )


def test_debt_is_reported_not_hidden() -> None:
    """The number is recorded where a reader can see it."""
    current = evidence_debt.compute()
    baseline = json.loads(evidence_debt.BASELINE.read_text(encoding="utf-8"))
    assert current["obligated"], "no product files were found at all"
    assert baseline["count"] <= len(current["obligated"]), (
        "baseline claims more unnamed files than there are product files"
    )
