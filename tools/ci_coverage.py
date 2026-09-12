#!/usr/bin/env python3
"""T17 (Steps 46-52) CI matrix checker.

Cross-language CI coverage with canonical/support semantics:

    CANONICAL required missing = FAIL (exit code 1).
    CANONICAL required non-success = FAIL (exit code 1).
    SUPPORT = reported, non-fatal (never gates canonical health).
    Optional = documented gap, non-fatal.

Every project declares a `job` name and a `classification` (CANONICAL or
SUPPORT). The checker scans the configured workflow YAML files and verifies
each job name appears as a `job:` key.

Usage:
    python tools/ci_coverage.py                 # matrix + pass/fail exit
    python tools/ci_coverage.py --json          # machine-readable result
    python tools/ci_coverage.py --manifest      # also require runtime_manifest REAL
    python tools/ci_coverage.py --needs-json J  # gate on upstream job results

`--needs-json` receives the GitHub Actions `toJSON(needs)` payload. Any
canonical required project whose job did not finish with `result == "success"`
-- including `failure`, `skipped`, `cancelled` and `absent` -- is reported as
FAIL. Support jobs are reported but never gate canonical health.
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
        classification = project.get("classification", "CANONICAL")
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
            "classification": classification,
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


def gate_job() -> str | None:
    """The job that runs this gate. It must never be evaluated against its own
    `needs` map, or the gate would always report itself as absent."""
    return load_coverage().get("gate_job")


def required_jobs() -> dict[str, bool]:
    """Map every CI job named by the coverage matrix to whether the matrix
    requires it. A job is required when at least one project marks it so.
    The gate job itself is excluded."""
    skip = gate_job()
    jobs: dict[str, bool] = {}
    for project in load_coverage().get("projects", []):
        job = project["job"]
        if job == skip:
            continue
        jobs[job] = jobs.get(job, False) or bool(project.get("required", False))
    return jobs


def check_results(needs: dict) -> dict:
    """Evaluate upstream job results. Non-success is FAIL for required jobs
    and a reported (non-fatal) observation for optional ones."""
    rows: list[dict] = []
    failed_required: list[str] = []
    for job, required in sorted(required_jobs().items()):
        entry = needs.get(job) or {}
        outcome = entry.get("result") or "absent"
        ok = outcome == "success"
        if not ok and required:
            status = "FAIL"
            failed_required.append(f"{job}={outcome}")
        elif not ok:
            status = "PASS (optional, reported)"
        else:
            status = "PASS"
        rows.append({"job": job, "required": required, "result": outcome,
                     "status": status})
    return {"jobs": rows, "failed_required": failed_required,
            "exit": 1 if failed_required else 0}


def main() -> int:
    ap = argparse.ArgumentParser(description="AEGIS cross-language CI matrix check")
    ap.add_argument("--json", action="store_true", help="emit machine-readable result")
    ap.add_argument("--manifest", action="store_true",
                    help="also require ci tooling REAL in runtime_manifest.json")
    ap.add_argument("--needs-json", metavar="JSON",
                    help="evaluate upstream job results (GitHub Actions toJSON(needs))")
    args = ap.parse_args()

    if args.needs_json is not None:
        try:
            needs = json.loads(args.needs_json or "{}")
        except json.JSONDecodeError as exc:
            print(f"FAIL: --needs-json is not valid JSON: {exc}")
            return 1
        res = check_results(needs)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print("Required canonical CI job results (failure/skipped/cancelled = FAIL)")
            print("-" * 72)
            for row in res["jobs"]:
                req = "required" if row["required"] else "optional"
                print(f"  {row['job']:<28} {req:<9} {row['result']:<10} {row['status']}")
            print("-" * 72)
            if res["failed_required"]:
                print("FAIL: required job(s) did not succeed: "
                      + ", ".join(res["failed_required"]))
            else:
                print("OK: every required job finished successfully")
        return res["exit"]

    result = check_matrix()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("Cross-language CI matrix (canonical required missing = FAIL; support = reported, non-fatal)")
        print(f"Workflows scanned: {', '.join(result['workflows_scanned'])}")
        print("-" * 72)
        for p in result["projects"]:
            req = "required" if p["required"] else "optional"
            cls = p["classification"]
            print(f"  {p['project']:<16} {p['language']:<10} {cls:<10} {p['job']:<24} "
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