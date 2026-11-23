#!/usr/bin/env python3
"""Validate EVIDENCE_INDEX.json against what it actually claims (S1-03).

Four defects this closes:

1. ``evidence_level_summary`` counted the ``known_gaps`` section as evidence.
   ``tools/evidence_debt.py`` states the correct rule ("Only evidence entries
   count as evidence. The known_gaps section is a findings log"), so the
   release-facing number (``E5_count: 166``) was 77 real entries plus 89 open
   gaps. Counts are now derived from ``evidence`` only, and
   ``E5_with_artifact_count`` publishes how many of them an auditor can open.
2. An E5 entry with no artifact pointer is an unfalsifiable claim. Such an
   entry must now carry ``artifact_status: "unrecorded"`` (or ``missing`` /
   ``historical``), so the omission is visible instead of implied.
3. Entries asserting ``host_effect_confirmed: true`` must be marked as
   lab-scoped or historical. This product is detection-only; an unmarked
   "host effect confirmed" row reads as a live enforcement claim.
4. A truthy ``evidence_artifact`` pointer is not proof that the artifact can
   be opened. Unresolvable pointers must now carry an explicit
   ``artifact_status``: ``historical`` with an ``artifact_locator`` (operator
   archive), or ``missing`` with an ``artifact_status_basis``. The summary
   publishes resolvable and unresolvable counts separately; an unlabeled
   missing pointer still fails validation.

Usage:
    python scripts/check_summary.py           # validate (exit 1 on drift)
    python scripts/check_summary.py --write   # recompute + mark, then validate
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

INDEX = Path(__file__).resolve().parents[1] / "EVIDENCE_INDEX.json"
LEVELS = ("E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7")
ARTIFACT_STATUSES = {"unrecorded", "missing", "historical"}


def load() -> dict:
    with open(INDEX, "r", encoding="utf-8") as f:
        return json.load(f)


def save(d: dict) -> None:
    INDEX.write_text(json.dumps(d, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def resolves(pointer: str) -> bool:
    return (INDEX.parent / pointer).exists()


def recompute(d: dict) -> dict:
    """Summary derived from evidence entries only, plus artifact visibility.

    ``E5_with_artifact_count`` stays as the historical count of truthy
    pointers, but it is explicitly NOT an openable-artifact count. The two new
    fields split it into what an auditor can read in this worktree and what
    they cannot.
    """
    counts = Counter(e.get("level") for e in d.get("evidence", []) if e.get("level"))
    e5 = [e for e in d.get("evidence", []) if e.get("level") == "E5"]
    e5_with_artifact = [e for e in e5 if e.get("evidence_artifact")]
    all_with_artifact = [e for e in d.get("evidence", []) if e.get("evidence_artifact")]
    summary = {f"{lvl}_count": counts.get(lvl, 0) for lvl in LEVELS}
    summary["E5_with_artifact_count"] = len(e5_with_artifact)
    summary["E5_with_resolvable_artifact_count"] = sum(
        1 for e in e5_with_artifact if resolves(e["evidence_artifact"])
    )
    summary["E5_with_unresolvable_artifact_count"] = sum(
        1 for e in e5_with_artifact if not resolves(e["evidence_artifact"])
    )
    summary["unresolvable_artifact_pointer_count"] = sum(
        1 for e in all_with_artifact if not resolves(e["evidence_artifact"])
    )
    summary["known_gaps_count"] = len(d.get("known_gaps", []))
    return summary


def mark(d: dict) -> bool:
    """Add the honesty markers the rules require. Returns True when it wrote."""
    changed = False
    for e in d.get("evidence", []):
        if e.get("level") == "E5" and not e.get("evidence_artifact"):
            if e.get("artifact_status") not in ARTIFACT_STATUSES:
                e["artifact_status"] = "unrecorded"
                changed = True
    for section in ("evidence", "known_gaps"):
        for e in d.get(section, []):
            if e.get("host_effect_confirmed") is True:
                if e.get("scope") != "lab" and e.get("historical") is not True:
                    e["scope"] = "lab"
                    e["historical"] = True
                    changed = True
    return changed


def validate(d: dict) -> list[str]:
    problems: list[str] = []
    summary = d.get("evidence_level_summary", {})
    actual = recompute(d)

    for key, value in actual.items():
        if summary.get(key) != value:
            problems.append(f"{key}: recorded {summary.get(key)}, actual {value}")

    root = INDEX.parent
    for e in d.get("evidence", []):
        level = e.get("level")
        if level == "E5" and not e.get("evidence_artifact"):
            if e.get("artifact_status") not in ARTIFACT_STATUSES:
                problems.append(
                    f"{e.get('id')}: E5 claim with no artifact pointer and no artifact_status marker"
                )
        pointer = e.get("evidence_artifact")
        if pointer and not (root / pointer).exists():
            status = e.get("artifact_status")
            if status not in {"historical", "missing"}:
                problems.append(
                    f"{e.get('id')}: unresolvable pointer needs artifact_status "
                    f"historical|missing: {pointer}"
                )
            elif status == "historical" and not str(e.get("artifact_locator") or "").strip():
                problems.append(
                    f"{e.get('id')}: historical artifact needs artifact_locator: {pointer}"
                )
            elif status == "missing" and not str(e.get("artifact_status_basis") or "").strip():
                problems.append(
                    f"{e.get('id')}: missing artifact needs artifact_status_basis: {pointer}"
                )

    for section in ("evidence", "known_gaps"):
        for e in d.get(section, []):
            if e.get("host_effect_confirmed") is True and not (
                e.get("scope") == "lab" or e.get("historical") is True
            ):
                problems.append(
                    f"{e.get('id')}: host_effect_confirmed=true without scope=lab/historical"
                )
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write", action="store_true", help="recompute the summary and add required markers")
    args = ap.parse_args(argv)

    d = load()
    if args.write:
        wrote = mark(d)
        d["evidence_level_summary"] = recompute(d)
        save(d)
        print(f"WROTE {INDEX.name} (markers_added={wrote})")

    summary = d.get("evidence_level_summary", {})
    print("Evidence level summary (evidence section only):")
    for key, value in summary.items():
        print(f"  {key}: {value}")

    evidence = d.get("evidence", [])
    gaps = d.get("known_gaps", [])
    with_pointer = [e for e in evidence if e.get("evidence_artifact")]
    unresolvable = [e for e in with_pointer if not resolves(e["evidence_artifact"])]
    print()
    print(f"evidence entries: {len(evidence)} (with artifact pointer: {len(with_pointer)})")
    print(f"artifact pointers resolvable in worktree: {len(with_pointer) - len(unresolvable)}")
    for e in unresolvable:
        print(f"  UNRESOLVABLE {e.get('id')}: {e.get('evidence_artifact')} "
              f"[{e.get('artifact_status')}]")
    print(f"known_gaps entries: {len(gaps)} (findings log, never counted as evidence)")

    problems = validate(d)
    if problems:
        print()
        print("EVIDENCE_INDEX INVALID:")
        for p in problems:
            print(f"  {p}")
        return 1

    print()
    print("SUMMARY_VALID: summary and artifact/scope markers match the entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
