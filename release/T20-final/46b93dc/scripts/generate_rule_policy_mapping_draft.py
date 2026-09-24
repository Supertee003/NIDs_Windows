"""Generate a non-active Rule-to-Policy mapping draft for Rules.json."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "configs" / "Rules.json"
OUT_JSON = ROOT / "analysis" / "RULE_22_POLICY_MAPPING_DRAFT.json"
OUT_MD = ROOT / "analysis" / "RULE_22_POLICY_MAPPING_DRAFT.md"


def canonical_action(configured: str) -> str:
    value = configured.strip().lower()
    if value == "alert":
        return "ALERT"
    if value in {"block", "drop"}:
        return "BLOCK"
    raise ValueError(f"unsupported configured action: {configured}")


def main() -> None:
    rules = json.loads(RULES.read_text(encoding="utf-8"))["nids_rules"]
    if len(rules) != 22:
        raise SystemExit(f"expected 22 rules, found {len(rules)}")

    mappings = []
    for rule in rules:
        action = canonical_action(rule["action"])
        mappings.append(
            {
                "rule_id": rule["rule_id"],
                "policy_key": f"rule:{rule['rule_id']}:v1",
                "policy_id": None,
                "configured_action": rule["action"],
                "canonical_action": action,
                "severity": rule["severity"],
                "layer": rule["layer"],
                "sensor": {
                    "L4": "wfp_kernel_telemetry",
                    "L7": "payload_sensor_pending",
                    "KERNEL_FILE": "fim_telemetry",
                    "KERNEL_PROCESS": "etw_process_telemetry",
                    "L2_PIPE": "pipe_telemetry",
                }[rule["layer"]],
                "qualification_mode": "DETECT_ONLY",
                "block_allowed": False,
                "mapping_status": "DRAFT_NOT_LOADED",
                "required_before_activation": [
                    "explicit_policy_id",
                    "signed_policy_envelope",
                    "canonical_action_conversion_test",
                    "rule_detection_fixture",
                    "enforcement_receipt_v1",
                    "host_postcondition_proof",
                    "exact_cleanup_proof",
                ],
            }
        )

    document = {
        "schema": "aegis.rule-policy-mapping-draft.v1",
        "active": False,
        "runtime_load_path": None,
        "source": "configs/Rules.json",
        "rule_count": len(mappings),
        "global_prevention_gate": "closed",
        "normalization": {
            "Drop": "BLOCK",
            "Block": "BLOCK",
            "Alert": "ALERT",
        },
        "note": "This is qualification metadata only. It must not be loaded as an active policy until every required gate passes.",
        "mappings": mappings,
    }
    OUT_JSON.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        "# Rules 22 Rule-to-Policy Mapping Draft",
        "",
        "> **Inactive draft:** this file is qualification metadata only. It is not loaded by the daemon and cannot authorize WFP enforcement.",
        "",
        "| Rule | Config action | Canonical action | Layer | Sensor | Mode | Block allowed | Status |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for item in mappings:
        lines.append(
            f"| `{item['rule_id']}` | `{item['configured_action']}` | `{item['canonical_action']}` | `{item['layer']}` | `{item['sensor']}` | `{item['qualification_mode']}` | `{str(item['block_allowed']).lower()}` | `{item['mapping_status']}` |"
        )
    lines += [
        "",
        "## Activation rule",
        "",
        "A mapping may become active only after assignment of a stable policy ID, signed policy-envelope verification, cross-language action conversion tests, a detection fixture, a complete EnforcementReceipt v1, host postcondition proof, exact cleanup proof, and a stale-filter scan.",
        "",
        "Until then every row remains `DETECT_ONLY` and `block_allowed=false`.",
    ]
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"generated {OUT_JSON}")
    print(f"generated {OUT_MD}")
    print(f"mappings={len(mappings)} active=false")


if __name__ == "__main__":
    main()
