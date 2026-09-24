"""Generate a deterministic qualification matrix for the configured NIDS rules."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "configs" / "Rules.json"
POLICIES_PATH = ROOT / "configs" / "policies.json"
OUT_JSON = ROOT / "analysis" / "RULE_22_QUALIFICATION_MATRIX.json"
OUT_MD = ROOT / "analysis" / "RULE_22_QUALIFICATION_MATRIX.md"


def capability(layer: str) -> tuple[str, str, str]:
    if layer == "L4":
        return (
            "wfp_network_telemetry",
            "kernel network 5-tuple telemetry is implemented; end-to-end proof pending",
            "KERNEL_WFP_E2E",
        )
    if layer == "L7":
        return (
            "user_or_application_payload",
            "current WFP callout exports 5-tuple only; payload match needs an application/proxy sensor",
            "L7_SENSOR_MAPPING",
        )
    if layer == "KERNEL_FILE":
        return (
            "fim_or_file_telemetry",
            "FIM worker exists; per-rule trigger and block postcondition require proof",
            "FILE_RULE_PROOF",
        )
    if layer == "KERNEL_PROCESS":
        return (
            "etw_process_telemetry",
            "ETW worker readiness exists; hids_process_monitor implementation is not complete",
            "PROCESS_SENSOR_PROOF",
        )
    if layer == "L2_PIPE":
        return (
            "pipe_telemetry",
            "pipe sensor path exists; per-rule event production and block semantics require proof",
            "PIPE_RULE_PROOF",
        )
    return ("unknown", "sensor mapping is undefined", "SENSOR_MAPPING")


def initial_status(action: str) -> str:
    # Config action is intent only. No rule is promoted to blocking before proof.
    return "DETECT_ONLY" if action.lower() == "alert" else "BLOCK_CANDIDATE_PENDING_PROOF"


def main() -> None:
    rules_doc = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    policies_doc = json.loads(POLICIES_PATH.read_text(encoding="utf-8"))
    rules = rules_doc["nids_rules"]
    if len(rules) != 22:
        raise SystemExit(f"expected 22 rules, found {len(rules)}")

    rows = []
    for rule in rules:
        sensor, limitation, blocker = capability(rule["layer"])
        rows.append(
            {
                "rule_id": rule["rule_id"],
                "name": rule["name"],
                "category": rule["category"],
                "layer": rule["layer"],
                "severity": rule["severity"],
                "configured_action": rule["action"],
                "initial_qualification": initial_status(rule["action"]),
                "sensor": sensor,
                "sensor_assessment": limitation,
                "qualification_blocker": blocker,
                "target_ports": rule.get("target_ports", []),
                "target_protocols": rule.get("target_protocols", []),
                "evidence_required": [
                    "matched_rule_id",
                    "canonical_event",
                    "forensic_record",
                    "false_positive_check",
                    "host_effect_none_or_confirmed",
                ],
                "ips_evidence_required": [
                    "policy_authorized",
                    "enforcement_receipt_v1",
                    "host_postcondition",
                    "exact_filter_cleanup",
                    "no_stale_filter",
                ],
            }
        )

    output = {
        "schema": "aegis.rule-qualification.v1",
        "source_rules": "configs/Rules.json",
        "source_policies": "configs/policies.json",
        "rule_count": len(rows),
        "generic_policy_count": len(policies_doc.get("policies", [])),
        "global_gate": "closed",
        "note": "configured action is not proof of enforcement; every rule remains unpromoted until evidence gates pass",
        "rules": rows,
    }
    OUT_JSON.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        "# AEGIS Rules 22 Qualification Matrix",
        "",
        "> This matrix is a baseline for controlled qualification. A configured `Block` or `Drop` action is an intent, not evidence that host enforcement is production-approved.",
        "",
        f"- Rules in `configs/Rules.json`: **{len(rows)}**",
        f"- Generic policies in `configs/policies.json`: **{len(policies_doc.get('policies', []))}**",
        "- Global prevention gate: **closed**",
        "- Initial rule statuses: `DETECT_ONLY` for Alert; `BLOCK_CANDIDATE_PENDING_PROOF` for Block/Drop",
        "",
        "## Matrix",
        "",
        "| Rule | Layer | Severity | Config action | Initial qualification | Sensor assessment | Blocker |",
        "|---|---|---:|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| `{row['rule_id']}` {row['name']} | `{row['layer']}` | {row['severity']} | `{row['configured_action']}` | `{row['initial_qualification']}` | {row['sensor_assessment']} | `{row['qualification_blocker']}` |"
        )
    lines += [
        "",
        "## Required evidence per rule",
        "",
        "Every rule must first produce a matched canonical event, the expected rule ID, a verified forensic record, and a false-positive result without unintended host effect.",
        "",
        "A rule may move from `BLOCK_CANDIDATE_PENDING_PROOF` to `BLOCK_PROVEN` only after policy authorization, a complete `EnforcementReceipt v1`, host postcondition confirmation, exact filter cleanup, and a stale-filter scan pass.",
        "",
        "## Immediate blockers",
        "",
        "1. `configs/policies.json` contains six generic policies but no direct 22-rule mapping.",
        "2. TypeScript, Zig, and Rust action ordinals must be frozen to one shared contract.",
        "3. L7 rules require a payload-aware sensor; the current WFP callout exports a network 5-tuple, not HTTP payload content.",
        "4. Process-layer rules require real event production proof; `hids_process_monitor.zig` is not a complete event source.",
        "5. No rule is promoted to blocking until the controlled WFP proof is completed on an isolated Windows test target.",
    ]
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"generated {OUT_JSON}")
    print(f"generated {OUT_MD}")
    print(f"rules={len(rows)} generic_policies={len(policies_doc.get('policies', []))}")


if __name__ == "__main__":
    main()
