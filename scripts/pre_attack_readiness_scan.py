#!/usr/bin/env python3
"""Deterministic, observe-only readiness scan for the 22-rule qualification set."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "analysis" / "RULE_22_QUALIFICATION_MATRIX.json"
MANIFEST = ROOT / "analysis" / "RULE_22_DETECTION_FIXTURE_MANIFEST.json"

REQUIRED_SAFETY = {
    "No real network transmission",
    "No executable payload",
    "No file mutation",
    "No process creation",
    "No named-pipe creation",
    "No enforcement.block request",
}
FORBIDDEN_TRUE_FLAGS = {
    "payload_execution",
    "network_transmission",
    "file_mutation",
    "process_creation",
    "pipe_creation",
}


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="write Markdown report to this path")
    args = parser.parse_args()

    matrix = load(MATRIX)
    manifest = load(MANIFEST)
    rules = matrix.get("rules", [])
    fixtures = manifest.get("fixtures", [])
    rule_ids = {r.get("rule_id") for r in rules}
    fixture_rule_ids = {f.get("rule_id") for f in fixtures}
    errors: list[str] = []
    warnings: list[str] = []

    if matrix.get("rule_count") != 22 or len(rules) != 22:
        errors.append(f"matrix rule count is {matrix.get('rule_count')} metadata/{len(rules)} records")
    if manifest.get("rule_count") != 22 or len(fixtures) != 22:
        errors.append(f"manifest rule count is {manifest.get('rule_count')} metadata/{len(fixtures)} records")
    if rule_ids != fixture_rule_ids:
        errors.append(f"matrix/fixture ID mismatch: matrix_only={sorted(rule_ids - fixture_rule_ids)} fixture_only={sorted(fixture_rule_ids - rule_ids)}")
    if matrix.get("global_gate") != "closed":
        errors.append("qualification global_gate is not closed")
    if manifest.get("active") is not False or manifest.get("execution_mode") != "synthetic_observe_only":
        errors.append("fixture manifest is not inactive synthetic_observe_only")
    if set(manifest.get("safety_contract", [])) != REQUIRED_SAFETY:
        errors.append("manifest safety_contract differs from required observe-only contract")

    for fixture in fixtures:
        fixture_id = fixture.get("fixture_id", "unknown")
        synthetic = fixture.get("synthetic_input", {})
        for flag in FORBIDDEN_TRUE_FLAGS:
            if synthetic.get(flag) is True:
                errors.append(f"{fixture_id}: forbidden synthetic_input.{flag}=true")
        expected = fixture.get("expected_observe_only", {})
        if expected.get("host_effect") != "none":
            errors.append(f"{fixture_id}: expected host_effect is not none")
        if expected.get("wfp_block") is not False or expected.get("enforcement_receipt") is not False:
            errors.append(f"{fixture_id}: observe-only enforcement expectation is unsafe")
        if fixture.get("status") != "READY_FOR_SENSOR_ADAPTER":
            warnings.append(f"{fixture_id}: status={fixture.get('status')}")

    blockers = Counter(r.get("qualification_blocker") for r in rules)
    layers = Counter(r.get("layer") for r in rules)
    qualifications = Counter(r.get("initial_qualification") for r in rules)
    if all(r.get("initial_qualification") == "BLOCK_CANDIDATE_PENDING_PROOF" for r in rules):
        warnings.append("all rules remain pending proof; no promotion is permitted")

    status = "PASS" if not errors else "FAIL"
    lines = [
        "# AEGIS Pre-Attack Readiness Scan",
        "",
        f"**Status:** `{status}`",
        "",
        "This scan is deterministic and observe-only. It validates qualification artifacts; it does not create processes, files, pipes, network traffic, or enforcement requests.",
        "",
        "## Baseline",
        "",
        f"- Matrix rules: `{len(rules)}` (declared `{matrix.get('rule_count')}`)",
        f"- Fixture rules: `{len(fixtures)}` (declared `{manifest.get('rule_count')}`)",
        f"- Global gate: `{matrix.get('global_gate')}`",
        f"- Fixture mode: `{manifest.get('execution_mode')}`; active=`{manifest.get('active')}`",
        "",
        "## Coverage by layer",
        "",
        "| Layer | Rules |",
        "|---|---:|",
    ]
    lines.extend(f"| `{key}` | {value} |" for key, value in sorted(layers.items()))
    lines += ["", "## Qualification blockers", "", "| Blocker | Rules |", "|---|---:|"]
    lines.extend(f"| `{key}` | {value} |" for key, value in sorted(blockers.items()))
    lines += ["", "## Initial qualification", "", "| State | Rules |", "|---|---:|"]
    lines.extend(f"| `{key}` | {value} |" for key, value in sorted(qualifications.items()))
    lines += ["", "## Findings", ""]
    if errors:
        lines += [f"- **ERROR:** {item}" for item in errors]
    else:
        lines.append("- No artifact or safety-contract errors detected.")
    lines += [f"- **NOTE:** {item}" for item in warnings]
    lines += ["", "## Gate decision", "", "The global prevention gate remains closed. Synthetic fixture readiness is not evidence of host detection or enforcement, and no attack simulation should begin until the relevant sensor-specific proof gate is opened through a separate reviewed step.", ""]
    report = "\n".join(lines)
    print(report)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report + "\n", encoding="utf-8")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
