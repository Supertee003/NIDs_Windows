#!/usr/bin/env python3
"""Rebuild and verify AEGIS truth/provenance artifacts.

This command is intentionally conservative: it regenerates artifacts for which
canonical generators exist, validates JSON structure, runs the repository truth
verifier, and records unresolved artifacts instead of rewriting SHA fields by
hand.
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "PHASE_0_TRUTH_REBUILD_REPORT.json"


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


def main() -> int:
    head = git_head()
    steps = [
        run("inventory/reference", [sys.executable, "tools/generate_truth_artifacts.py"]),
        run("runtime manifest", [sys.executable, "tools/create_manifest.py"]),
        run("truth verifier", [sys.executable, "tools/truth.py", "verify"]),
    ]

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
    unresolved = [
        item["file"] for item in validation
        if not item["exists"] or not item["valid_json"]
    ]
    if verifier["returncode"] != 0:
        unresolved.extend([
            line.split()[0]
            for line in verifier["stdout"].splitlines()
            if "STALE" in line or "NO_SHA" in line or "MISSING" in line
        ])

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": head,
        "steps": steps,
        "json_validation": validation,
        "unresolved": sorted(set(unresolved)),
        "machine_map_rebuild": {
            "status": "NOT_RUN",
            "reason": "No canonical current-head generator was found for the four machine maps and evidence index; do not rewrite SHA fields manually.",
            "files": [
                "SYSTEM_MAP.json",
                "FLOW_MAP.json",
                "AUTHORITY_MAP.json",
                "CONTRACT_MAP.json",
                "EVIDENCE_INDEX.json",
            ],
        },
        "valid": verifier["returncode"] == 0 and not unresolved,
    }
    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "head": head,
        "valid": report["valid"],
        "unresolved": report["unresolved"],
        "report": str(REPORT),
    }, indent=2, ensure_ascii=False))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
