"""R-11: detection-only is a property of the tree, not a promise in a document.

The product decision is that no production path may block or mutate traffic.
Until slice B1 retires the authority, six files still contain a block action
(`analysis/current-head/detection-only-baseline.json`). This gate makes that
list a closed set: a seventh file that introduces a block action fails here,
before it can be built, shipped, or quietly justified in review.

The same scan tells B1 when it is finished: when the allowlist is empty and the
scan is clean, the enforcement surface is gone.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "analysis" / "current-head" / "detection-only-baseline.json"

# Directories that produce shipped code. Docs, tests and analysis are allowed
# to discuss enforcement: they are not executable product surface.
SCAN_ROOTS = ("src", "drivers", "rust-src", "bridge", "mouth", "shield", "go")


def _baseline() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def _tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", *SCAN_ROOTS],
        capture_output=True, text=True, cwd=ROOT, check=True,
    ).stdout
    return [p for p in out.splitlines() if p]


def _scan(tokens: list[str]) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for rel in _tracked_files():
        path = ROOT / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        found = [t for t in tokens if t in text]
        if found:
            hits[rel] = found
    return hits


def test_no_new_enforcement_site_appears() -> None:
    data = _baseline()
    allowed = {e["path"] for e in data["allowed"]}
    hits = _scan(data["tokens"])

    unexpected = {p: t for p, t in hits.items() if p not in allowed}
    assert not unexpected, (
        "new enforcement surface in product code (detection-only is the "
        "recorded product decision):\n  "
        + "\n  ".join(f"{p}: {', '.join(t)}" for p, t in sorted(unexpected.items()))
        + "\nIf this is legitimate evidence about a retired path, add it to "
        "analysis/current-head/detection-only-baseline.json with a reason."
    )


def test_baseline_has_no_phantom_entries() -> None:
    data = _baseline()
    hits = _scan(data["tokens"])
    stale = [e["path"] for e in data["allowed"] if e["path"] not in hits]
    assert not stale, (
        "baseline lists files that no longer contain a block action; trim them "
        f"so the count reflects reality: {stale}"
    )


def test_baseline_entries_state_why_they_are_allowed() -> None:
    data = _baseline()
    thin = [e["path"] for e in data["allowed"] if not e.get("reason")]
    assert not thin, f"allowlist entries without a reason: {thin}"
    assert len(data["tokens"]) >= 3, "the scan must cover block action, IOCTL and symbol"
