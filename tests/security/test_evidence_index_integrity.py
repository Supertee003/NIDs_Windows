"""R-02 / R-13: the evidence index must not over-claim or point at nothing.

Two failures this test catches that prose review does not:

R-02 — an entry that claims a host-level grade (E5) while carrying no build
anchor. An E5 claim without a hash is a memory, not a measurement. Two
historical entries predate the rule and are allowlisted by id, so the test
fails on any new one instead of rewriting history.

R-13 — an entry whose artifact path no longer exists. Deletions are allowed,
but the index has to follow them.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "EVIDENCE_INDEX.json"
HOLLOW = ROOT / "analysis" / "current-head" / "hollow-evidence-baseline.json"
LEVELS = {"E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7"}

# Historical entries written before the anchor rule. Do not add to this set;
# fix the entry instead.
E5_WITHOUT_ANCHOR = {"VOL02-BUILD-001", "VOL10-CLI-001"}

HEX = re.compile(r"\b[0-9a-f]{7,40}\b")


def _index() -> dict:
    return json.loads(INDEX.read_text(encoding="utf-8"))


def test_entry_ids_are_unique_and_levels_are_valid() -> None:
    entries = _index()["evidence"]
    ids = [e["id"] for e in entries]
    dupes = [i for i, n in Counter(ids).items() if n > 1]
    assert not dupes, f"duplicate evidence ids: {dupes}"

    bad = [
        (e.get("id"), e.get("level"))
        for e in entries
        if e.get("level") not in LEVELS
    ]
    assert not bad, f"invalid evidence levels: {bad}"


def test_every_new_entry_says_what_it_is() -> None:
    """31 historical entries are hollow; the list may only shrink."""
    baseline = json.loads(HOLLOW.read_text(encoding="utf-8"))["ids"]
    entries = _index()["evidence"]
    hollow = [
        e.get("id")
        for e in entries
        if not (e.get("title") or "").strip()
        or not (e.get("description") or "").strip()
        or not (e.get("component") or "").strip()
    ]
    added = sorted(set(hollow) - set(baseline))
    assert not added, (
        "new evidence entries with no title/description/component: "
        f"{added}"
    )
    closed = sorted(set(baseline) - set(hollow))
    assert not closed, (
        "these entries now have a shape, so the baseline is stale: "
        f"{closed} - trim analysis/current-head/hollow-evidence-baseline.json"
    )


def test_artifact_paths_exist() -> None:
    missing: list[str] = []
    for entry in _index()["evidence"]:
        for rel in entry.get("artifacts") or []:
            if not (ROOT / rel).exists():
                missing.append(f"{entry['id']} -> {rel}")
    assert not missing, "evidence points at files that no longer exist:\n  " + (
        "\n  ".join(missing)
    )


def test_host_level_claims_carry_a_build_anchor() -> None:
    offenders = []
    for entry in _index()["evidence"]:
        if entry.get("level") not in {"E5", "E6", "E7"}:
            continue
        if entry["id"] in E5_WITHOUT_ANCHOR:
            continue
        if not HEX.search(json.dumps(entry, ensure_ascii=False)):
            offenders.append(entry["id"])
    assert not offenders, (
        "host-level evidence without a build anchor (hash of the measured "
        f"artifact): {offenders}"
    )


def test_level_summary_matches_entries() -> None:
    # S1-03 (2026-11-10): only `evidence` counts. `known_gaps` is a findings
    # log; including it inflated E5_count to 166 (77 evidence + 89 gaps).
    data = _index()
    counts = Counter(
        e["level"]
        for e in data.get("evidence", [])
        if e.get("level")
    )
    summary = data["evidence_level_summary"]
    mismatched = {
        lvl: (summary.get(f"{lvl}_count"), counts.get(lvl, 0))
        for lvl in sorted(LEVELS)
        if summary.get(f"{lvl}_count") != counts.get(lvl, 0)
    }
    assert not mismatched, f"level summary drift (recorded, actual): {mismatched}"


def test_host_effect_claims_are_marked_lab_or_historical() -> None:
    """This product is detection-only; a host-effect claim must be scoped."""
    offenders = [
        e.get("id")
        for key in ("evidence", "known_gaps")
        for e in _index().get(key, [])
        if e.get("host_effect_confirmed") is True
        and not (e.get("scope") == "lab" or e.get("historical") is True)
    ]
    assert not offenders, (
        "host_effect_confirmed=true without scope=lab/historical: "
        f"{offenders}"
    )


def test_e5_entries_disclose_whether_an_artifact_exists() -> None:
    """An E5 without an openable artifact must say so, not imply one."""
    offenders = [
        e.get("id")
        for e in _index()["evidence"]
        if e.get("level") == "E5"
        and not e.get("evidence_artifact")
        and e.get("artifact_status") not in {"unrecorded", "missing", "historical"}
    ]
    assert not offenders, (
        "E5 entries with no artifact pointer and no artifact_status marker: "
        f"{offenders}"
    )
