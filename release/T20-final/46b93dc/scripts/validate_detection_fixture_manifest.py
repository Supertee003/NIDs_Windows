"""Validate that the Rules 22 fixture manifest remains synthetic and observe-only."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "analysis" / "RULE_22_DETECTION_FIXTURE_MANIFEST.json"


def main() -> int:
    doc = json.loads(MANIFEST.read_text(encoding="utf-8"))
    errors: list[str] = []
    fixtures = doc.get("fixtures", [])

    if doc.get("active") is not False:
        errors.append("manifest active must be false")
    if doc.get("execution_mode") != "synthetic_observe_only":
        errors.append("execution_mode must be synthetic_observe_only")
    if doc.get("global_prevention_gate") != "closed":
        errors.append("global_prevention_gate must be closed")
    if len(fixtures) != 22 or doc.get("rule_count") != 22:
        errors.append("manifest must contain exactly 22 fixtures")

    seen_rules: set[str] = set()
    for fixture in fixtures:
        rule_id = fixture.get("rule_id")
        if not rule_id or rule_id in seen_rules:
            errors.append(f"duplicate or missing rule_id: {rule_id!r}")
        seen_rules.add(rule_id)
        synthetic = fixture.get("synthetic_input", {})
        expected = fixture.get("expected_observe_only", {})
        forbidden_true = (
            "payload_execution",
            "network_transmission",
            "file_mutation",
            "process_creation",
            "pipe_creation",
        )
        for field in forbidden_true:
            if synthetic.get(field) is not False:
                errors.append(f"{rule_id}: {field} must be false")
        if expected.get("host_effect") != "none":
            errors.append(f"{rule_id}: host_effect must be none")
        if expected.get("wfp_block") is not False:
            errors.append(f"{rule_id}: wfp_block must be false")
        if expected.get("enforcement_receipt") is not False:
            errors.append(f"{rule_id}: enforcement_receipt must be false")
        if expected.get("canonical_event") is not True:
            errors.append(f"{rule_id}: canonical_event must be true")
        if expected.get("forensic_record") is not True:
            errors.append(f"{rule_id}: forensic_record must be true")

    result = {"passed": not errors, "fixture_count": len(fixtures), "errors": errors}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
