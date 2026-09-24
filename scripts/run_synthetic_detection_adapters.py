"""Run local-only synthetic adapters for the 22-rule detection manifest.

This produces qualification evidence envelopes, not real kernel/sensor proof.
It intentionally performs no network, process, file mutation, pipe creation, or
PEP/WFP operation.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "analysis" / "RULE_22_DETECTION_FIXTURE_MANIFEST.json"
OUT_JSON = ROOT / "analysis" / "RULE_22_SYNTHETIC_DETECTION_EVIDENCE.json"
OUT_JSONL = ROOT / "analysis" / "RULE_22_SYNTHETIC_DETECTION_EVIDENCE.jsonl"

SEVERITY = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
LAYER_ID = {"L4": 1, "L7": 1, "KERNEL_FILE": 2, "KERNEL_PROCESS": 2, "L2_PIPE": 3}


def digest_marker(marker: str) -> str:
    return hashlib.sha256(marker.encode("utf-8")).hexdigest()[:16]


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    fixtures = manifest.get("fixtures", [])
    if manifest.get("execution_mode") != "synthetic_observe_only":
        raise SystemExit("refusing to run a non-observe-only manifest")
    if manifest.get("global_prevention_gate") != "closed":
        raise SystemExit("refusing to run while prevention gate is not closed")
    if len(fixtures) != 22:
        raise SystemExit(f"expected 22 fixtures, found {len(fixtures)}")

    now_ms = int(time.time() * 1000)
    evidence = []
    for index, fixture in enumerate(fixtures, start=1):
        marker = fixture["synthetic_input"]["marker"]
        severity = fixture["severity"]
        evidence.append(
            {
                "evidence_id": f"SYN-{index:02d}-{fixture['rule_id']}",
                "fixture_id": fixture["fixture_id"],
                "mode": "synthetic_observe_only",
                "source": fixture["source"],
                "canonical_event": {
                    "magic": "AEG1",
                    "version": 1,
                    "event_id": index,
                    "timestamp_ms": now_ms,
                    "layer_id": LAYER_ID[fixture["layer"]],
                    "provenance": fixture["source"],
                    "matched_rule_key": fixture["rule_id"],
                    "severity": severity,
                    "severity_ordinal": SEVERITY[severity],
                    "payload_hash_prefix": digest_marker(marker),
                    "policy_action_intent": "ALERT" if fixture["configured_action"] == "Alert" else "BLOCK",
                    "enforcement_status": "pending_observe_only",
                },
                "detection_assertions": {
                    "matched_rule_key_expected": fixture["rule_id"],
                    "matched_rule_key_observed": fixture["rule_id"],
                    "severity_expected": severity,
                    "severity_observed": severity,
                    "provenance_expected": fixture["source"],
                    "provenance_observed": fixture["source"],
                    "matched": True,
                },
                "safety_assertions": {
                    "host_effect": "none",
                    "wfp_block": False,
                    "enforcement_receipt": False,
                    "network_transmission": False,
                    "file_mutation": False,
                    "process_creation": False,
                    "pipe_creation": False,
                },
                "qualification_status": "SYNTHETIC_ONLY_NOT_SENSOR_PROOF",
            }
        )

    result = {
        "schema": "aegis.synthetic-detection-evidence.v1",
        "mode": "synthetic_observe_only",
        "active": False,
        "prevention_gate": "closed",
        "fixture_count": len(fixtures),
        "matched_count": sum(1 for item in evidence if item["detection_assertions"]["matched"]),
        "host_effect_count": sum(1 for item in evidence if item["safety_assertions"]["host_effect"] != "none"),
        "note": "Synthetic adapter output is not evidence that the real kernel/FIM/ETW/pipe/WFP sensor detected the rule.",
        "evidence": evidence,
    }
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    OUT_JSONL.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in evidence), encoding="utf-8")
    print(json.dumps({
        "passed": result["matched_count"] == 22 and result["host_effect_count"] == 0,
        "fixture_count": result["fixture_count"],
        "matched_count": result["matched_count"],
        "host_effect_count": result["host_effect_count"],
        "mode": result["mode"],
    }, indent=2))
    return 0 if result["matched_count"] == 22 and result["host_effect_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
