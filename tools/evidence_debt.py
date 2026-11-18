#!/usr/bin/env python3
"""Compute the evidence-debt baseline (R-03 ratchet).

A tracked file inside a product unit must be named by some evidence entry.
Today 500 of 652 are not. That number may only go down: this tool writes the
exact set of currently-unnamed files, and tests/security/test_scope_ratchet.py
fails if the set grows or if it shrinks without the baseline being trimmed.

Usage:
    python tools/evidence_debt.py            # report only
    python tools/evidence_debt.py --write    # rewrite the baseline
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "EVIDENCE_INDEX.json"
BASELINE = ROOT / "analysis" / "current-head" / "evidence-debt-baseline.json"
WORK_MAPS = sorted((ROOT / "analysis" / "current-head").glob("WORK-MAP-*.json"))

# Statuses that carry an evidence obligation.
OBLIGATED = {"IN_PRODUCT", "IN_PRODUCT_ADVISORY", "CONTRACT"}


def work_map() -> dict:
    if not WORK_MAPS:
        raise SystemExit("no WORK-MAP-*.json found under analysis/current-head/")
    data = json.loads(WORK_MAPS[-1].read_text(encoding="utf-8"))
    return {u["unit"]: u["status"] for u in data["units"]}


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, cwd=ROOT, check=True
    ).stdout
    return [p for p in out.splitlines() if p]


def compute() -> dict:
    status = work_map()
    # Only evidence entries count as evidence. The known_gaps section is a
    # findings log: it mentions paths without proving anything about them.
    index = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    evidence_text = "\n".join(
        json.dumps(e, ensure_ascii=False) for e in index["evidence"]
    )
    obligated: list[str] = []
    unnamed: list[str] = []
    for path in tracked_files():
        unit = path.split("/")[0] if "/" in path else "<root>"
        if status.get(unit) not in OBLIGATED:
            continue
        obligated.append(path)
        if path not in evidence_text:
            unnamed.append(path)
    return {
        "obligated": obligated,
        "unnamed": sorted(unnamed),
    }


def main(argv: list[str]) -> int:
    data = compute()
    unnamed = data["unnamed"]
    print(f"product-tracked files: {len(data['obligated'])}")
    print(f"never named by evidence: {len(unnamed)}")
    if "--write" in argv:
        source = subprocess.run(
            ["git", "log", "-1", "--format=%h", "--", "src", "build.zig", "CMakeLists.txt"],
            capture_output=True, text=True, cwd=ROOT,
        ).stdout.strip()
        BASELINE.write_text(
            json.dumps(
                {
                    "id": "EVIDENCE-DEBT-BASELINE",
                    "rule": "unnamed product files may shrink but never grow; "
                            "trim this file in the same patch that names one",
                    "source_commit": source,
                    "count": len(unnamed),
                    "unnamed": unnamed,
                },
                indent=2,
                ensure_ascii=False,
            ) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(f"wrote {BASELINE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
