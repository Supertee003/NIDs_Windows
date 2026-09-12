#!/usr/bin/env python3
"""Truth Artifact Verifier — single source of truth consistency gate.

Verifies that every truth artifact in the repository carries the current
HEAD SHA. Any mismatch means the artifact is STALE and the agent is
reading outdated truth.

Usage:
    python tools/truth.py verify          # human-readable output
    python tools/truth.py verify --json   # machine-readable output
    python tools/truth.py verify --strict # also fail on missing files

Exit codes:
    0  TRUTH_VALID   — all artifacts carry current HEAD
    1  TRUTH_INVALID — at least one artifact has stale/missing HEAD
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── Artifact definitions ──────────────────────────────────────────
# Each entry: (file_path, field_type, field_name)
# field_type: "head_sha" | "source_commit" | "markdown_head" | "none"

JSON_HEAD_SHA = [
    "SYSTEM_MAP.json",
    "FLOW_MAP.json",
    "AUTHORITY_MAP.json",
    "CONTRACT_MAP.json",
    "EVIDENCE_INDEX.json",
    "build_truth.json",
    "runtime_manifest.json",
]

JSON_SOURCE_COMMIT = [
    "build_manifest.json",
]

MARKDOWN_HEAD = [
    "AI_CONTEXT.md",
]

NO_SHA_EXPECTED = [
    "inventory.json",
    "reference_map.json",
]


def git_head() -> str:
    """Return full 40-char HEAD SHA."""
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True, text=True, cwd=ROOT,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git rev-parse HEAD failed: {result.stderr.strip()}")
    return result.stdout.strip()


def read_json_head_sha(path: Path) -> str | None:
    """Extract head_sha from a JSON file's top-level field."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("head_sha")
    except (json.JSONDecodeError, KeyError):
        return None


def read_json_source_commit(path: Path) -> str | None:
    """Extract source_commit from a JSON file's top-level field."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("source_commit")
    except (json.JSONDecodeError, KeyError):
        return None


def read_markdown_head(path: Path) -> str | None:
    """Extract HEAD SHA from AI_CONTEXT.md **HEAD:** line."""
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    m = re.search(r"\*\*HEAD:\*\*\s*`([0-9a-f]{40})`", text)
    return m.group(1) if m else None


def verify(strict: bool = False) -> dict:
    """Run all checks. Returns a result dict."""
    head = git_head()
    head_short = head[:7]
    results = []
    all_ok = True

    # JSON files with head_sha (full 40-char)
    for fname in JSON_HEAD_SHA:
        path = ROOT / fname
        artifact_sha = read_json_head_sha(path)
        if artifact_sha is None:
            status = "MISSING" if not path.exists() else "NO_SHA"
            ok = not strict
        elif artifact_sha == head:
            status = "PASS"
            ok = True
        else:
            status = "STALE"
            ok = False
        if not ok:
            all_ok = False
        results.append({
            "file": fname,
            "type": "head_sha",
            "expected": head,
            "actual": artifact_sha,
            "status": status,
        })

    # JSON files with source_commit (7-char abbreviated)
    for fname in JSON_SOURCE_COMMIT:
        path = ROOT / fname
        artifact_sha = read_json_source_commit(path)
        if artifact_sha is None:
            status = "MISSING" if not path.exists() else "NO_SHA"
            ok = not strict
        elif artifact_sha == head_short:
            status = "PASS"
            ok = True
        else:
            status = "STALE"
            ok = False
        if not ok:
            all_ok = False
        results.append({
            "file": fname,
            "type": "source_commit",
            "expected": head_short,
            "actual": artifact_sha,
            "status": status,
        })

    # Markdown files with **HEAD:** inline
    for fname in MARKDOWN_HEAD:
        path = ROOT / fname
        artifact_sha = read_markdown_head(path)
        if artifact_sha is None:
            status = "MISSING" if not path.exists() else "NO_SHA"
            ok = not strict
        elif artifact_sha == head:
            status = "PASS"
            ok = True
        else:
            status = "STALE"
            ok = False
        if not ok:
            all_ok = False
        results.append({
            "file": fname,
            "type": "markdown_head",
            "expected": head,
            "actual": artifact_sha,
            "status": status,
        })

    # Files with no SHA (expected — documented)
    for fname in NO_SHA_EXPECTED:
        path = ROOT / fname
        exists = path.exists()
        results.append({
            "file": fname,
            "type": "none",
            "expected": "N/A (no SHA field)",
            "actual": "N/A",
            "status": "PASS (no SHA expected)" if exists else "MISSING",
        })

    return {
        "head": head,
        "valid": all_ok,
        "results": results,
    }


def print_human(res: dict) -> None:
    head = res["head"]
    print(f"HEAD: {head}")
    print("-" * 72)
    for r in res["results"]:
        actual = r["actual"] or "—"
        if len(actual) > 20:
            actual = actual[:12] + "…"
        print(f"  {r['file']:<28} {r['type']:<14} {r['status']}")
    print("-" * 72)
    if res["valid"]:
        print("TRUTH_VALID — all artifacts carry current HEAD")
    else:
        stale = [r["file"] for r in res["results"] if r["status"] == "STALE"]
        print(f"TRUTH_INVALID — stale artifacts: {', '.join(stale)}")


def main() -> int:
    ap = argparse.ArgumentParser(description="AEGIS truth artifact verifier")
    ap.add_argument("command", choices=["verify"], help="subcommand")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--strict", action="store_true",
                    help="also fail on missing SHA fields")
    args = ap.parse_args()

    if args.command == "verify":
        res = verify(strict=args.strict)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print_human(res)
        return 0 if res["valid"] else 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
