#!/usr/bin/env python3
"""T17 (Steps 46-52) CI matrix checker.

Cross-language CI coverage with required/optional semantics:

    A project marked "required" that has NO matching CI job -> FAIL
    (exit code 1). A project marked "optional" with no job -> reported and
    PASS (documented gap).

Every project declares a `job` name. The checker scans the configured
workflow YAML files and verifies each job name appears as a `job:` key.

Usage:
    python tools/ci_coverage.py                 # matrix + pass/fail exit
    python tools/ci_coverage.py --json          # machine-readable result
    python tools/ci_coverage.py --manifest      # also require runtime_manifest REAL
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COVERAGE = ROOT / "ci_coverage.json"


def load_coverage() -> dict:
    return json.loads(COVERAGE.read_text(encoding="utf-8"))


def workflow_job_names(workflow: Path) -> set[str]:
    """Very small YAML subset parser: collect indented `name:`/`job:` keys
    under `jobs:` that are followed by a colon block opener. We key on the
    literal job id lines (e.g. `  zig-build-test:`)."""
    if not workflow.exists():
        return set()
    jobs: set[str] = set()
    in_jobs = False
    for raw in workflow.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        # A top-level job key under jobs: has 2-space indent and no dash.
        if line.startswith("  ") and not line.startswith("    ") and stripped.endswith(":"):
            jobs.add(stripped[:-1])
    return jobs


def check_matrix() -> dict:
    coverage = load_coverage()
    job_ids: set[str] = set()
    for wf in coverage.get("workflows", []):
        job_ids |= workflow_job_names(ROOT / wf)

    results: list[dict] = []
    failed_required: list[str] = []
    optional_gaps: list[str] = []
    for project in coverage.get("projects", []):
        pid = project["id"]
        job = project["job"]
        required = project.get("required", False)
        key = f"{pid}->{job}"
        present = job in job_ids
        if present:
            status = "PASS"
        elif required:
            status = "FAIL"
            failed_required.append(key)
        else:
            status = "PASS (optional, documented gap)"
            optional_gaps.append(key)
        results.append({
            "project": pid,
            "language": project["language"],
            "job": job,
            "required": required,
            "present": present,
            "status": status,
        })

    return {
        "gate_semantics": coverage.get("gate_semantics", ""),
        "workflows_scanned": [wf for wf in coverage.get("workflows", [])],
        "projects": results,
        "failed_required": failed_required,
        "optional_gaps": optional_gaps,
        "exit": 1 if failed_required else 0,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="AEGIS cross-language CI matrix check")
    ap.add_argument("--json", action="store_true", help="emit machine-readable result")
    ap.add_argument("--manifest", action="store_true",
                    help="also require ci tooling REAL in runtime_manifest.json")
    args = ap.parse_args()

    result = check_matrix()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("Cross-language CI matrix (required missing = FAIL; optional = PASS, documented)")
        print(f"Workflows scanned: {', '.join(result['workflows_scanned'])}")
        print("-" * 72)
        for p in result["projects"]:
            req = "required" if p["required"] else "optional"
            print(f"  {p['project']:<16} {p['language']:<10} {p['job']:<24} "
                  f"{req:<9} {p['status']}")
        print("-" * 72)
        if result["failed_required"]:
            print(f"FAIL: required projects without a CI job: {', '.join(result['failed_required'])}")
        else:
            print(f"OK: every required project has a CI job "
                  f"({'coverage complete' if not result['optional_gaps'] else 'optional gaps documented: ' + ', '.join(result['optional_gaps'])})")

    if args.manifest and not args.json:
        manifest = json.loads((ROOT / "runtime_manifest.json").read_text(encoding="utf-8"))
        for mod in ("tools/ci_coverage.py", "ci_coverage.json"):
            entry = manifest["modules"].get(mod)
            if not entry or entry.get("status") != "REAL":
                print(f"FAIL: manifest does not mark {mod} REAL")
                return 1

    return result["exit"]


if __name__ == "__main__":
    sys.exit(main())