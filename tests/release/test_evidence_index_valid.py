"""EVIDENCE-INDEX-098: the evidence registry must always parse and agree.

Gap closed here: a JSON syntax error in EVIDENCE_INDEX.json went unnoticed
because no test parsed the file — truth.py is non-strict (NO_SHA still
reports VALID) and no pytest test read the index. This test is pure
read-only: it parses the index and re-derives the level summary from the
entries themselves, so a broken file or a stale summary fails loudly.
No tree writes.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
INDEX = REPO / "EVIDENCE_INDEX.json"
LEVELS = ("E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7")


def _load() -> dict:
    return json.loads(INDEX.read_text(encoding="utf-8"))


def test_no_duplicate_keys_anywhere():
    # Guard: json.loads silently lets the LAST duplicate key win, so a
    # double-written evidence_level_summary hid a stale count (EVT-118).
    # Re-parse with an object_pairs hook that rejects any repeated key.
    def reject_dupes(pairs):
        keys = [k for k, _ in pairs]
        dupes = {k for k in keys if keys.count(k) > 1}
        assert not dupes, f"duplicate JSON keys: {sorted(dupes)}"
        return dict(pairs)

    json.loads(INDEX.read_text(encoding="utf-8"), object_pairs_hook=reject_dupes)


def test_index_parses_as_json():
    d = _load()
    assert isinstance(d, dict)
    assert isinstance(d.get("known_gaps"), list)
    assert isinstance(d.get("evidence_level_summary"), dict)


def test_level_summary_matches_entries():
    # Counting rule (corrected 2026-11-10, S1-03): only the `evidence`
    # section is evidence. `known_gaps` is a findings log — counting it
    # inflated E5_count to 166 (77 evidence + 89 open gaps). tools/evidence_debt.py
    # has always used this rule; scripts/check_summary.py now matches it.
    d = _load()
    actual = Counter(
        e["level"]
        for e in d.get("evidence", [])
        if e.get("level")
    )
    summary = d["evidence_level_summary"]
    for lvl in LEVELS:
        assert summary.get(f"{lvl}_count") == actual.get(lvl, 0), lvl

    e5 = [e for e in d["evidence"] if e.get("level") == "E5"]
    with_artifact = [e for e in e5 if e.get("evidence_artifact")]
    assert summary.get("E5_with_artifact_count") == len(with_artifact)
    resolvable = [e for e in with_artifact
                  if (INDEX.parent / e["evidence_artifact"]).exists()]
    assert summary.get("E5_with_resolvable_artifact_count") == len(resolvable)
    assert summary.get("E5_with_unresolvable_artifact_count") == len(with_artifact) - len(resolvable)
    all_ptr = [e for e in d["evidence"] if e.get("evidence_artifact")]
    all_resolvable = [e for e in all_ptr
                      if (INDEX.parent / e["evidence_artifact"]).exists()]
    assert summary.get("unresolvable_artifact_pointer_count") == len(all_ptr) - len(all_resolvable)
    assert summary.get("known_gaps_count") == len(d.get("known_gaps", []))


def test_unresolvable_artifact_pointers_carry_explicit_status():
    # P3-EVIDENCE-HONESTY: a truthy pointer is not proof an auditor can open
    # the artifact. Historical pointers name an operator-archive locator;
    # genuinely lost pointers state why they are not independently auditable.
    bad = []
    for e in _load().get("evidence", []):
        pointer = e.get("evidence_artifact")
        if not pointer or (INDEX.parent / pointer).exists():
            continue
        status = e.get("artifact_status")
        if status not in {"historical", "missing"}:
            bad.append(f"{e.get('id')}: bad status {status!r}")
        elif status == "historical" and not str(e.get("artifact_locator") or "").strip():
            bad.append(f"{e.get('id')}: missing artifact_locator")
        elif status == "missing" and not str(e.get("artifact_status_basis") or "").strip():
            bad.append(f"{e.get('id')}: missing artifact_status_basis")
    assert not bad, f"unlabeled unresolved artifact pointers: {bad[:10]}"
