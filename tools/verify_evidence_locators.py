#!/usr/bin/env python3
"""Report which unresolved evidence artifacts have a locator that exists.

This is a read-only diagnostic, not a gate and not a proof of any evidence
level. It distinguishes:

  repo-resolvable  - artifact_locator points at a tracked worktree path
  archive-resolvable - artifact_locator points at an operator archive path
  missing          - no locator, or the locator does not exist here

It never copies local-only evidence into the repository and never changes a
status or level in EVIDENCE_INDEX.json.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "EVIDENCE_INDEX.json"


def main() -> int:
    data = json.loads(INDEX.read_text(encoding="utf-8"))
    counts = {"repo-resolvable": 0, "archive-resolvable": 0, "missing": 0}
    rows = []
    for entry in data.get("evidence", []):
        art = entry.get("evidence_artifact")
        status = entry.get("artifact_status")
        if not art or status not in ("missing", "historical"):
            continue
        locator = entry.get("artifact_locator")
        kind = "missing"
        if locator:
            path = Path(locator)
            if not path.is_absolute():
                path = ROOT / path
            if path.exists():
                kind = "repo-resolvable" if str(ROOT) in str(path.resolve()) else "archive-resolvable"
        counts[kind] += 1
        rows.append((entry.get("id", "?"), kind, art, locator))
    print("UNRESOLVED ARTIFACT LOCATOR REPORT")
    for key in ("repo-resolvable", "archive-resolvable", "missing"):
        print(f"  {key}: {counts[key]}")
    print(f"  total: {len(rows)}")
    if "--verbose" in sys.argv:
        for eid, kind, art, locator in rows:
            print(f"  {kind:18} {eid} | {art} | {locator}")
    print("Read-only diagnostic: no artifact was copied and no level was changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
