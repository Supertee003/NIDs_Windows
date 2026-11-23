"""GAP-STATUS-001: every known gap must say whether it is open.

Before this slice, `EVIDENCE_INDEX.known_gaps` had 227 entries with **no**
`status` field at all, plus three one-off status strings (`PASS`,
`CLOSED_BY_EVT-008`, `E5_VERIFIED_TOTAL_LOSS_OPEN`). A reader could not tell an
open defect from a closed one without reading every description, and the count of
open gaps was unknowable — which is exactly the number a release decision needs.

The fix is classification, not reassessment: entries written before the field
existed are marked `UNRECORDED`, meaning "not re-verified", never "closed".
Nothing here claims a gap was fixed.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "EVIDENCE_INDEX.json"

ALLOWED = {"OPEN", "CLOSED", "CLOSED_AT_RECORDED_HEAD", "UNRECORDED"}


def _index() -> dict:
    return json.loads(INDEX.read_text(encoding="utf-8"))


def test_every_gap_has_a_supported_status() -> None:
    gaps = _index().get("known_gaps") or []
    assert gaps
    bad = [
        f"{gap.get('id')}: {gap.get('status')!r}"
        for gap in gaps
        if gap.get("status") not in ALLOWED
    ]
    assert not bad, f"unsupported gap status values: {bad[:10]}"


def test_gap_ids_are_unique_and_named() -> None:
    ids = [gap.get("id") for gap in (_index().get("known_gaps") or [])]
    assert all(isinstance(gap_id, str) and gap_id.strip() for gap_id in ids)
    duplicates = sorted({gap_id for gap_id in ids if ids.count(gap_id) > 1})
    assert not duplicates, f"duplicate gap ids: {duplicates}"


def test_an_open_gap_says_what_blocks_it() -> None:
    """An open gap with no next step is a note, not a tracked item."""
    offenders = [
        gap.get("id")
        for gap in (_index().get("known_gaps") or [])
        if gap.get("status") == "OPEN"
        and not (gap.get("blocked_by") or gap.get("next_step") or gap.get("fix"))
    ]
    assert not offenders, f"open gaps without a blocker, next step or fix: {offenders}"


def test_the_index_explains_what_unrecorded_means() -> None:
    note = _index().get("known_gaps_status_note") or ""
    assert "UNRECORDED" in note
    assert "not" in note.lower(), "the note must say an unrecorded gap is not a closed one"


def test_a_historical_closure_carries_its_basis() -> None:
    """`CLOSED_AT_RECORDED_HEAD` must name a real SHA and a recorded result.

    P3-EVIDENCE-HONESTY: `head_sha: null`, a malformed SHA, or a closure with
    no `result` field cannot support the status. Those entries must be
    `UNRECORDED` instead of claiming a verified past head.
    """
    offenders = []
    for gap in (_index().get("known_gaps") or []):
        if gap.get("status") != "CLOSED_AT_RECORDED_HEAD":
            continue
        gap_id = gap.get("id")
        head = gap.get("head_sha")
        if not re.fullmatch(r"[0-9a-f]{7,40}", str(head or "")):
            offenders.append(f"{gap_id}: invalid head_sha {head!r}")
        if not str(gap.get("status_basis") or "").strip():
            offenders.append(f"{gap_id}: missing status_basis")
        if not str(gap.get("result") or "").strip():
            offenders.append(f"{gap_id}: missing result")
    assert not offenders, f"unsupported historical closures: {offenders}"


def test_the_note_distinguishes_a_historical_closure_from_a_current_one() -> None:
    note = _index().get("known_gaps_status_note") or ""
    assert "CLOSED_AT_RECORDED_HEAD" in note
    assert "re-verif" in note, "the note must say a historical closure is not re-verified"
