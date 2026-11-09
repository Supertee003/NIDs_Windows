#!/usr/bin/env python3
"""Truth Artifact Verifier — single source of truth consistency gate.

Truth artifacts carry the *build source commit*: the last commit that touched
the source/build tree (ADR-0008). They do not carry the commit that merely
records evidence, because a commit cannot contain its own SHA.

The verifier:
  1. computes the source commit with `git log -1 -- <SOURCE_PATHS>`,
  2. requires every head_sha/markdown_head/source_commit field to carry it,
  3. requires the source commit to be an ancestor of HEAD,
  4. requires the source paths to be clean between the source and HEAD, and
  5. requires the source/build worktree itself to be clean (tracked changes and
     untracked source/build files both invalidate the maps).

A records-only commit therefore does not invalidate truth artifacts; a source
or build change after the recorded source does. Uncommitted source/build work
is never current truth either.

Usage:
    python tools/truth.py verify          # human-readable output
    python tools/truth.py verify --json   # machine-readable output
    python tools/truth.py verify --strict # also fail on missing files

Exit codes:
    0  TRUTH_VALID   — artifacts carry the current build source commit
    1  TRUTH_INVALID — stale/mis-stamped artifact or dirty source tree
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── Build source boundary (ADR-0008) ──────────────────────────────
# A commit that touches any of these paths produces new build inputs and must
# move the recorded source commit. Everything else (docs, evidence, tests,
# tooling, CI metadata) is records-only and must NOT move it.
SOURCE_PATHS = (
    "src",
    "rust-src",
    "shield",
    "nose",
    "go",
    "brain",
    "drivers",
    "shared",
    "bridge",
    "mouth",
    "configs",
    "build.zig",
    "Cargo.toml",
    "Cargo.lock",
    "CMakeLists.txt",
    "requirements.txt",
    # The WDK scripts are the only definition of the kernel compile/link
    # flags; CMake delegates to them. They are build inputs, unlike the
    # evidence/signing/deployment wrappers that consume their output.
    "scripts/wdk_build_production.ps1",
    "scripts/wdk_build_minifilter.ps1",
)

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
    # R-04: these two carry source_commit too. They used to be exempt, which is
    # exactly how a stale inventory stayed invisible.
    "inventory.json",
    "reference_map.json",
]

MARKDOWN_HEAD = [
    "AI_CONTEXT.md",
]

NO_SHA_EXPECTED: list[str] = []


def git_head() -> str:
    """Return full 40-char HEAD SHA."""
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True, text=True, cwd=ROOT,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git rev-parse HEAD failed: {result.stderr.strip()}")
    return result.stdout.strip()


def git_source() -> str:
    """Return the full SHA of the last commit touching the source/build tree."""
    result = subprocess.run(
        ["git", "log", "-1", "--format=%H", "--", *SOURCE_PATHS],
        capture_output=True, text=True, cwd=ROOT,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git log source paths failed: {result.stderr.strip()}")
    source = result.stdout.strip()
    if not source:
        raise RuntimeError("no commit touches the source/build paths")
    return source


def is_ancestor(commit: str, head: str) -> bool:
    """True when commit is an ancestor of (or equal to) head."""
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, head],
        capture_output=True, text=True, cwd=ROOT,
    )
    return result.returncode == 0


def source_tree_clean(source: str, head: str) -> bool:
    """True when no source/build path changed between source and head."""
    result = subprocess.run(
        ["git", "diff", "--quiet", source, head, "--", *SOURCE_PATHS],
        capture_output=True, text=True, cwd=ROOT,
    )
    return result.returncode == 0


def source_worktree_changes() -> list[str]:
    """Return tracked or untracked changes under the source/build paths.

    Committed history alone is not enough: a dirty source tree means the maps
    were generated from different bytes than the ones a build would use now.
    Untracked source files count as changes; ignored build outputs do not.
    """
    result = subprocess.run(
        [
            "git", "status", "--porcelain=v1", "--untracked-files=all",
            "--", *SOURCE_PATHS,
        ],
        capture_output=True, text=True, cwd=ROOT,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git status source paths failed: {result.stderr.strip()}"
        )
    return [line for line in result.stdout.splitlines() if line.strip()]


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
    """Run all checks against the build source commit. Returns a result dict."""
    head = git_head()
    source = git_source()
    source_short = source[:7]
    ancestor = is_ancestor(source, head)
    tree_clean = source_tree_clean(source, head) if ancestor else False
    worktree_changes = source_worktree_changes()
    worktree_clean = not worktree_changes
    results = []
    all_ok = ancestor and tree_clean and worktree_clean

    # The source commit itself is the provenance root for every artifact.
    results.append({
        "file": "<source-ancestry>",
        "type": "ancestry",
        "expected": f"ancestor of {head[:7]}",
        "actual": source_short,
        "status": "PASS" if ancestor else "NOT_ANCESTOR",
        "ok": ancestor,
    })
    results.append({
        "file": "<source-paths>",
        "type": "source_tree",
        "expected": "clean since source",
        "actual": "clean" if tree_clean else "changed",
        "status": "PASS" if tree_clean else "CHANGED",
        "ok": tree_clean,
    })
    results.append({
        "file": "<source-worktree>",
        "type": "worktree",
        "expected": "clean working tree",
        "actual": (
            "clean" if worktree_clean
            else f"dirty ({len(worktree_changes)} path(s)): "
            + ", ".join(worktree_changes[:3])
            + (" ..." if len(worktree_changes) > 3 else "")
        ),
        "status": "PASS" if worktree_clean else "DIRTY",
        "ok": worktree_clean,
    })

    # JSON files with head_sha (full 40-char)
    for fname in JSON_HEAD_SHA:
        path = ROOT / fname
        artifact_sha = read_json_head_sha(path)
        if artifact_sha is None:
            status = "MISSING" if not path.exists() else "NO_SHA"
            ok = not strict
        elif artifact_sha == source:
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
            "expected": source,
            "actual": artifact_sha,
            "status": status,
            "ok": ok,
        })

    # JSON files with source_commit (7-char abbreviated)
    for fname in JSON_SOURCE_COMMIT:
        path = ROOT / fname
        artifact_sha = read_json_source_commit(path)
        if artifact_sha is None:
            status = "MISSING" if not path.exists() else "NO_SHA"
            ok = not strict
        elif artifact_sha == source_short:
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
            "expected": source_short,
            "actual": artifact_sha,
            "status": status,
            "ok": ok,
        })

    # Markdown files with **HEAD:** inline
    for fname in MARKDOWN_HEAD:
        path = ROOT / fname
        artifact_sha = read_markdown_head(path)
        if artifact_sha is None:
            status = "MISSING" if not path.exists() else "NO_SHA"
            ok = not strict
        elif artifact_sha == source:
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
            "expected": source,
            "actual": artifact_sha,
            "status": status,
            "ok": ok,
        })

    # Files with no SHA (expected — documented, but the file must exist)
    for fname in NO_SHA_EXPECTED:
        path = ROOT / fname
        exists = path.exists()
        if not exists:
            all_ok = False
        results.append({
            "file": fname,
            "type": "none",
            "expected": "N/A (no SHA field)",
            "actual": "N/A",
            "status": "PASS (no SHA expected)" if exists else "MISSING",
            "ok": exists,
        })

    return {
        "head": head,
        "source": source,
        "source_short": source_short,
        "source_is_ancestor": ancestor,
        "source_paths_clean": tree_clean,
        "source_worktree_clean": worktree_clean,
        "source_worktree_changes": worktree_changes,
        "valid": all_ok,
        "results": results,
    }


def print_human(res: dict) -> None:
    head = res["head"]
    source = res["source"]
    print(f"HEAD:   {head}")
    print(f"SOURCE: {source}  (last commit touching the source/build tree)")
    print("-" * 72)
    for r in res["results"]:
        actual = r["actual"] or "—"
        if len(actual) > 20:
            actual = actual[:12] + "…"
        print(f"  {r['file']:<28} {r['type']:<14} {r['status']}")
    print("-" * 72)
    if res["valid"]:
        print(
            "TRUTH_VALID — artifacts carry build source "
            f"{res['source_short']} (ancestor of HEAD; source history and "
            "worktree clean)"
        )
    else:
        bad = [r["file"] for r in res["results"] if not r.get("ok", True)]
        print(f"TRUTH_INVALID — stale/mis-stamped artifacts: {', '.join(bad)}")


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
