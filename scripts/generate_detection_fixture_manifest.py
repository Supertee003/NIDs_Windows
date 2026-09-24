"""Generate safe synthetic detection fixtures for all configured Rules."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "configs" / "Rules.json"
OUT_JSON = ROOT / "analysis" / "RULE_22_DETECTION_FIXTURE_MANIFEST.json"
OUT_MD = ROOT / "analysis" / "RULE_22_DETECTION_FIXTURE_MANIFEST.md"

LAYER_SOURCE = {
    "L4": "synthetic_wfp_network_event",
    "L7": "synthetic_payload_event",
    "KERNEL_FILE": "synthetic_fim_event",
    "KERNEL_PROCESS": "synthetic_etw_process_event",
    "L2_PIPE": "synthetic_pipe_event",
}

# Representative abuse tokens appended to the marker so the synthetic signal
# satisfies the rule's own regex (VOL11-ATK-001). Marker-only: no execution,
# no transmission, no mutation — the token is a string in a JSON fixture.
# R2004 (certutil Download Abuse) requires lowercase "certutil" followed by
# -urlcache|-f; the fast pattern CERTUTIL stays intact at the head.
MARKER_TRIGGER = {
    "R2004": "certutil -urlcache",
}


def main() -> None:
    rules = json.loads(RULES.read_text(encoding="utf-8"))["nids_rules"]
    if len(rules) != 22:
        raise SystemExit(f"expected 22 rules, found {len(rules)}")

    fixtures = []
    for index, rule in enumerate(rules, start=1):
        layer = rule["layer"]
        fixture_id = f"FX-{index:02d}-{rule['rule_id']}"
        marker = rule["fast_pattern"]
        trigger = MARKER_TRIGGER.get(rule["rule_id"])
        if trigger:
            marker = f"{marker} {trigger}"
        fixtures.append(
            {
                "fixture_id": fixture_id,
                "rule_id": rule["rule_id"],
                "name": rule["name"],
                "layer": layer,
                "source": LAYER_SOURCE[layer],
                "severity": rule["severity"],
                "configured_action": rule["action"],
                "expected_detection": {
                    "matched_rule_id": rule["rule_id"],
                    "fast_pattern": rule["fast_pattern"],
                    "match_pattern": rule["match_pattern"],
                    "regex_pattern": rule["regex_pattern"],
                },
                "synthetic_input": {
                    "kind": "fixture_marker_only",
                    "marker": marker,
                    "payload_execution": False,
                    "network_transmission": False,
                    "file_mutation": False,
                    "process_creation": False,
                    "pipe_creation": False,
                },
                "expected_observe_only": {
                    "host_effect": "none",
                    "wfp_block": False,
                    "enforcement_receipt": False,
                    "forensic_record": True,
                    "canonical_event": True,
                },
                "status": "READY_FOR_SENSOR_ADAPTER",
            }
        )

    document = {
        "schema": "aegis.detection-fixture-manifest.v1",
        "active": False,
        "execution_mode": "synthetic_observe_only",
        "rule_count": len(fixtures),
        "global_prevention_gate": "closed",
        "safety_contract": [
            "No real network transmission",
            "No executable payload",
            "No file mutation",
            "No process creation",
            "No named-pipe creation",
            "No enforcement.block request",
        ],
        "fixtures": fixtures,
    }
    OUT_JSON.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        "# Rules 22 Detection Fixture Manifest",
        "",
        "> Synthetic observe-only fixtures only. These markers are not attack execution and are not sent to the network, filesystem, process launcher, or enforcement path.",
        "",
        f"- Fixtures: **{len(fixtures)}**",
        "- Execution mode: `synthetic_observe_only`",
        "- Global prevention gate: **closed**",
        "",
        "| Fixture | Rule | Layer | Synthetic source | Marker | Expected action | Expected host effect | Status |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for item in fixtures:
        lines.append(
            f"| `{item['fixture_id']}` | `{item['rule_id']}` | `{item['layer']}` | `{item['source']}` | `{item['synthetic_input']['marker']}` | `{item['configured_action']}` | `none` | `{item['status']}` |"
        )
    lines += [
        "",
        "## Per-fixture acceptance",
        "",
        "Each adapter must emit a canonical event with the expected Rule key, preserve severity and provenance, create a forensic record, and produce no WFP filter, EnforcementReceipt, filesystem mutation, process creation, or real network transmission.",
        "",
        "The manifest does not claim that a sensor adapter is implemented. `READY_FOR_SENSOR_ADAPTER` means the fixture definition is ready for the relevant test harness.",
    ]
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"generated {OUT_JSON}")
    print(f"generated {OUT_MD}")
    print(f"fixtures={len(fixtures)} active=false")


if __name__ == "__main__":
    main()
