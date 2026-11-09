#!/usr/bin/env python3
"""Rebuild and verify AEGIS truth/provenance artifacts.

Truth artifacts carry the build source commit — the last commit that touched
the source/build tree (ADR-0008), not the commit that records evidence. This
command is conservative:

  1. regenerates artifacts that have canonical generators (inventory,
     reference_map, runtime_manifest),
  2. stamps the deterministic source commit into the machine maps,
     AI_CONTEXT, EVIDENCE_INDEX, build_manifest, build_truth and
     runtime_manifest (idempotent; the source comes from git, never a caller),
  3. validates JSON structure and runs the truth verifier.

A records-only commit therefore produces no dirty head overlay.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "PHASE_0_TRUTH_REBUILD_REPORT.json"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from truth import git_source  # noqa: E402 — tools/ is the script directory

HEAD_SHA_FILES = [
    "SYSTEM_MAP.json",
    "FLOW_MAP.json",
    "AUTHORITY_MAP.json",
    "CONTRACT_MAP.json",
    "EVIDENCE_INDEX.json",
    "build_truth.json",
    "runtime_manifest.json",
]

SOURCE_COMMIT_FILES = [
    "build_manifest.json",
    "runtime_manifest.json",
]

MARKDOWN_HEAD_FILES = [
    "AI_CONTEXT.md",
]


def run(label: str, command: list[str]) -> dict:
    proc = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    return {
        "label": label,
        "command": command,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def git_head() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()


def validate_json_files(names: list[str]) -> list[dict]:
    results = []
    for name in names:
        path = ROOT / name
        item = {"file": name, "exists": path.exists(), "valid_json": False}
        if path.exists():
            try:
                json.loads(path.read_text(encoding="utf-8"))
                item["valid_json"] = True
            except (OSError, json.JSONDecodeError) as exc:
                item["error"] = str(exc)
        results.append(item)
    return results


GENERATED_MAP_FILES = [
    "inventory.json",
    "reference_map.json",
]


def stamp_generated_maps(source_short: str) -> list[str]:
    """Ensure regenerated maps carry source_commit (R-04).

    The generators are deterministic but know nothing about git, so the stamp
    belongs here: after regeneration, before validation. Without it these two
    maps could lag the source commit and nothing would notice.
    """
    changed: list[str] = []
    for name in GENERATED_MAP_FILES:
        path = ROOT / name
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("source_commit") == source_short:
            continue
        data["source_commit"] = source_short
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8", newline="\n",
        )
        changed.append(name)
    return changed


def stamp_source(source: str, source_short: str) -> list[str]:
    """Rewrite head_sha/source_commit/HEAD fields to the source commit."""
    changed: list[str] = []

    for name in HEAD_SHA_FILES:
        path = ROOT / name
        text = path.read_text(encoding="utf-8")
        current = json.loads(text).get("head_sha")
        if not current or current == source:
            continue
        old = f'"head_sha": "{current}"'
        if old not in text:
            raise RuntimeError(f"{name}: head_sha field is not a literal string")
        path.write_text(text.replace(old, f'"head_sha": "{source}"', 1), encoding="utf-8")
        changed.append(name)

    for name in SOURCE_COMMIT_FILES:
        path = ROOT / name
        text = path.read_text(encoding="utf-8")
        current = json.loads(text).get("source_commit")
        if not current or current == source_short:
            continue
        old = f'"source_commit": "{current}"'
        if old not in text:
            raise RuntimeError(f"{name}: source_commit field is not a literal string")
        path.write_text(text.replace(old, f'"source_commit": "{source_short}"', 1), encoding="utf-8")
        if name not in changed:
            changed.append(name)

    for name in MARKDOWN_HEAD_FILES:
        path = ROOT / name
        text = path.read_text(encoding="utf-8")
        new_text, count = re.subn(
            r"(\*\*HEAD:\*\*\s*`)[0-9a-f]{40}(`)",
            lambda m: m.group(1) + source + m.group(2),
            text,
            count=1,
        )
        if count == 0:
            raise RuntimeError(f"{name}: no **HEAD:** line found")
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")
            changed.append(name)

    return changed


def main() -> int:
    head = git_head()
    source = git_source()
    source_short = source[:7]

    steps = [
        run("inventory/reference", [sys.executable, "tools/generate_truth_artifacts.py"]),
        run("runtime manifest", [sys.executable, "tools/create_manifest.py"]),
    ]
    changed = stamp_generated_maps(source_short)
    changed += [c for c in stamp_source(source, source_short) if c not in changed]
    steps.append({
        "label": "source stamp",
        "command": [],
        "returncode": 0,
        "stdout": f"source={source} changed={', '.join(changed) or 'none'}",
        "stderr": "",
    })
    steps.append(
        run("truth verifier", [sys.executable, "tools/truth.py", "verify", "--json"])
    )

    json_files = [
        "SYSTEM_MAP.json",
        "FLOW_MAP.json",
        "AUTHORITY_MAP.json",
        "CONTRACT_MAP.json",
        "EVIDENCE_INDEX.json",
        "build_truth.json",
        "runtime_manifest.json",
        "build_manifest.json",
        "inventory.json",
        "reference_map.json",
    ]
    validation = validate_json_files(json_files)
    verifier = steps[-1]

    verifier_result: dict = {}
    try:
        verifier_result = json.loads(verifier["stdout"])
    except json.JSONDecodeError:
        verifier_result = {}

    unresolved = [
        item["file"] for item in validation
        if not item["exists"] or not item["valid_json"]
    ]
    if not verifier_result:
        unresolved.append("truth-verifier")
    else:
        unresolved.extend(
            r["file"] for r in verifier_result.get("results", [])
            if not r.get("ok", True)
        )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": head,
        "source_commit": source,
        "source_short": source_short,
        "steps": steps,
        "json_validation": validation,
        "unresolved": sorted(set(unresolved)),
        "stamped": changed,
        "machine_map_rebuild": {
            "status": "SOURCE_STAMP",
            "reason": (
                "Maps carry the last commit touching the source/build tree "
                "(ADR-0008). The stamp is deterministic and idempotent; "
                "records-only commits do not move it."
            ),
            "files": HEAD_SHA_FILES + MARKDOWN_HEAD_FILES,
        },
        "valid": (
            verifier["returncode"] == 0
            and bool(verifier_result.get("valid"))
            and not unresolved
        ),
    }
    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "head": head,
        "source_commit": source,
        "source_short": source_short,
        "valid": report["valid"],
        "unresolved": report["unresolved"],
        "stamped": changed,
        "report": str(REPORT),
    }, indent=2, ensure_ascii=False))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
