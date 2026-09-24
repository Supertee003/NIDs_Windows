#!/usr/bin/env python3
"""Generate the Phase 8 controlled attack-lab scenario manifest.

Phase 8 target (AEGIS_END_TO_END_DEVELOPMENT_PLAN): prove the machine with
traffic whose scope, rate, and cleanup are controlled.

Scope rule: benign HTTP service plus inert markers only. No real malware, no
credential theft, no ransomware, no uncontrolled flood, and no executable
payload. Every marker below is a string that matches a shipped rule's regex
through its `INFO:<FAST_PATTERN>` form (or an inert literal), and nothing is
ever transmitted, written, spawned, or handed to enforcement.

Outputs:
  analysis/PHASE8_LAB_SCENARIO_MANIFEST.json
  analysis/PHASE8_LAB_SCENARIO_MANIFEST.md
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "configs" / "Rules.json"
OUT_JSON = ROOT / "analysis" / "PHASE8_LAB_SCENARIO_MANIFEST.json"
OUT_MD = ROOT / "analysis" / "PHASE8_LAB_SCENARIO_MANIFEST.md"

SCHEMA = "aegis.phase8-lab-scenario-manifest.v1"

# The seven scenario kinds defined by src/lab/scenario_contract.zig.
# The generator asserts 1:1 coverage so the manifest cannot drift from the
# Zig contract.
SCENARIO_KINDS = [
    "sql_marker",
    "command_marker",
    "xss_marker",
    "traversal_marker",
    "bounded_recon",
    "file_canary",
    "process_canary",
]

# Canonical config-action vocabulary. Must equal the table in
# src/policy/rule_action.zig; scripts/validate_phase8_lab_manifest.py
# cross-checks it against that source so the two cannot drift.
CONFIG_ACTION_TO_CANONICAL = {
    "Allow": ("pass", False),
    "Pass": ("pass", False),
    "Log": ("log", False),
    "Alert": ("alert", False),
    "RateLimit": ("rate_limit", True),
    "Drop": ("block", True),
    "Block": ("block", True),
    "Quarantine": ("quarantine", True),
    "Escalate": ("escalate", True),
}

# Bounds. Phase 8 requires bounded scope and rate.
GLOBAL_MAX_EVENTS_PER_SCENARIO = 8
GLOBAL_MAX_RATE_PER_SEC = 2
GLOBAL_MAX_SCENARIOS = 7

# Categories that must never appear in a lab scenario.
FORBIDDEN_CATEGORIES = [
    "real_malware",
    "credential_theft",
    "ransomware",
    "uncontrolled_flood",
    "exploit_execution",
    "data_exfiltration",
    "privilege_escalation",
]

SCENARIOS: list[dict] = [
    {
        "scenario_id": "LAB-SQL-001",
        "kind": "sql_marker",
        "category": "sql_injection_marker",
        "rule_id": "R0056",
        "target": "/lab/catalog?item=1",
        "marker": "INFO:SQLI_BYPASS",
        "vector": "benign_http_query_marker",
        "max_events": 4,
        "rate_limit_per_sec": 2,
        "requires_cleanup": True,
        "cleanup_method": "lab_http_session_close",
        "canary_expiry_s": 0,
        "notes": "Inert marker string; no query is executed against any database.",
    },
    {
        "scenario_id": "LAB-CMD-001",
        "kind": "command_marker",
        "category": "command_injection_marker",
        "rule_id": "R9064",
        "target": "/lab/ping?host=127.0.0.1",
        "marker": "INFO:OSI_SEMI",
        "vector": "benign_http_query_marker",
        "max_events": 4,
        "rate_limit_per_sec": 2,
        "requires_cleanup": True,
        "cleanup_method": "lab_http_session_close",
        "canary_expiry_s": 0,
        "notes": "Marker only; no process is spawned and no shell is invoked.",
    },
    {
        "scenario_id": "LAB-XSS-001",
        "kind": "xss_marker",
        "category": "xss_marker",
        "rule_id": "R9059",
        "target": "/lab/comment",
        "marker": "INFO:XSS_BASIC",
        "vector": "benign_http_body_marker",
        "max_events": 4,
        "rate_limit_per_sec": 2,
        "requires_cleanup": True,
        "cleanup_method": "lab_http_session_close",
        "canary_expiry_s": 0,
        "notes": "Marker only; never rendered by a browser and never stored.",
    },
    {
        "scenario_id": "LAB-TRAV-001",
        "kind": "traversal_marker",
        "category": "path_traversal_marker",
        "rule_id": "R0088",
        "target": "/lab/file?name=notes.txt",
        "marker": "/windows/win.ini",
        "vector": "benign_http_query_marker",
        "max_events": 4,
        "rate_limit_per_sec": 2,
        "requires_cleanup": True,
        "cleanup_method": "lab_http_session_close",
        "canary_expiry_s": 0,
        "notes": "Inert literal; the lab service never opens a filesystem path.",
    },
    {
        "scenario_id": "LAB-RECON-001",
        "kind": "bounded_recon",
        "category": "bounded_reconnaissance",
        "rule_id": "R9006",
        "target": "lab_hostonly_interface",
        "marker": "INFO:SYN_STEALTH",
        "vector": "synthetic_l4_flag_marker",
        "max_events": 8,
        "rate_limit_per_sec": 1,
        "requires_cleanup": True,
        "cleanup_method": "lab_recon_state_release",
        "canary_expiry_s": 60,
        "notes": "Bounded connect-count marker against a host-only interface; no scan is emitted.",
    },
    {
        "scenario_id": "LAB-FILE-001",
        "kind": "file_canary",
        "category": "benign_file_canary",
        "rule_id": "R1005",
        "target": "lab_canary_directory",
        "marker": "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "vector": "synthetic_fim_event_marker",
        "max_events": 2,
        "rate_limit_per_sec": 1,
        "requires_cleanup": True,
        "cleanup_method": "canary_file_restore",
        "canary_expiry_s": 60,
        "notes": "Inert path literal for a lab-authored canary file; the real hosts file is never touched.",
    },
    {
        "scenario_id": "LAB-PROC-001",
        "kind": "process_canary",
        "category": "benign_process_canary",
        "rule_id": "R3003",
        "target": "lab_canary_pipe",
        "marker": "INFO:ANON_PIPE",
        "vector": "synthetic_pipe_event_marker",
        "max_events": 2,
        "rate_limit_per_sec": 1,
        "requires_cleanup": True,
        "cleanup_method": "canary_pipe_release",
        "canary_expiry_s": 60,
        "notes": "Marker only; no named pipe is created and no process is started.",
    },
]


def canonical_action(config_action: str) -> tuple[str, bool]:
    if config_action not in CONFIG_ACTION_TO_CANONICAL:
        raise SystemExit(f"unmapped config action {config_action!r}")
    return CONFIG_ACTION_TO_CANONICAL[config_action]


def main() -> None:
    rules_by_id = {r["rule_id"]: r for r in json.loads(RULES.read_text(encoding="utf-8"))["nids_rules"]}

    if len(SCENARIOS) != GLOBAL_MAX_SCENARIOS:
        raise SystemExit(f"expected {GLOBAL_MAX_SCENARIOS} scenarios, found {len(SCENARIOS)}")
    kinds = [s["kind"] for s in SCENARIOS]
    if sorted(kinds) != sorted(SCENARIO_KINDS):
        raise SystemExit(f"scenario kinds do not cover src/lab/scenario_contract.zig: {kinds}")

    scenarios = []
    for spec in SCENARIOS:
        rule = rules_by_id.get(spec["rule_id"])
        if rule is None:
            raise SystemExit(f"{spec['scenario_id']}: unknown rule_id {spec['rule_id']}")
        if spec["max_events"] > GLOBAL_MAX_EVENTS_PER_SCENARIO:
            raise SystemExit(f"{spec['scenario_id']}: max_events exceeds global bound")
        if spec["rate_limit_per_sec"] > GLOBAL_MAX_RATE_PER_SEC:
            raise SystemExit(f"{spec['scenario_id']}: rate limit exceeds global bound")

        action, privileged = canonical_action(rule["action"])
        scenarios.append(
            {
                "scenario_id": spec["scenario_id"],
                "kind": spec["kind"],
                "category": spec["category"],
                "rule_id": rule["rule_id"],
                "name": rule["name"],
                "layer": rule["layer"],
                "target": spec["target"],
                "marker": spec["marker"],
                "vector": spec["vector"],
                "max_events": spec["max_events"],
                "rate_limit_per_sec": spec["rate_limit_per_sec"],
                "requires_cleanup": spec["requires_cleanup"],
                "cleanup_method": spec["cleanup_method"],
                "canary_expiry_s": spec["canary_expiry_s"],
                "notes": spec["notes"],
                "configured_action": rule["action"],
                "canonical_action": action,
                "privileged": privileged,
                "synthetic_input": {
                    "kind": "lab_marker_only",
                    "marker": spec["marker"],
                    "payload_execution": False,
                    "network_transmission": False,
                    "file_mutation": False,
                    "process_creation": False,
                    "pipe_creation": False,
                    "real_exploit": False,
                },
                "expected_decision": {
                    "detection": "REQUIRED",
                    "matched_rule_id": rule["rule_id"],
                    "severity": rule["severity"],
                    "configured_action": rule["action"],
                    "canonical_action": action,
                    "pep_expected": "BLOCK_OR_FAIL_CLOSED_ESCALATE",
                    "pep_authorization": "REQUIRED" if privileged else "NOT_REQUIRED",
                    "wfp_result": "UNAVAILABLE_UNTIL_HOST_VERIFIED",
                    "enforcement_receipt": "REQUIRED_IF_BLOCK",
                    "forensic_record": "REQUIRED",
                    "rollback": "REQUIRED",
                },
                "status": "READY_FOR_LAB_EXECUTION",
            }
        )

    document = {
        "schema": SCHEMA,
        "active": False,
        "execution_mode": "synthetic_observe_only",
        "global_prevention_gate": "closed",
        "topology": {
            "name": "wsl2_hostonly_lab",
            "isolation": "host_only_network",
            "benign_service": "lab_http_stub",
            "external_egress": False,
            "real_targets": False,
        },
        "bounds": {
            "global_max_events_per_scenario": GLOBAL_MAX_EVENTS_PER_SCENARIO,
            "global_max_rate_per_sec": GLOBAL_MAX_RATE_PER_SEC,
            "global_max_scenarios": GLOBAL_MAX_SCENARIOS,
        },
        "forbidden_categories": FORBIDDEN_CATEGORIES,
        "safety_contract": [
            "No real network transmission",
            "No executable payload",
            "No file mutation outside lab canaries",
            "No process creation",
            "No named-pipe creation",
            "No enforcement.block request while the prevention gate is closed",
            "Every scenario is rate limited and cleans up after itself",
        ],
        "scenario_count": len(scenarios),
        "scenarios": scenarios,
    }
    OUT_JSON.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        "# Phase 8 — Controlled Attack Lab Scenario Manifest",
        "",
        "> Inert markers only. Nothing in this manifest is transmitted, executed,",
        "> written, spawned, or handed to the enforcement path. The global",
        "> prevention gate is **closed**.",
        "",
        f"- Scenarios: **{len(scenarios)}**",
        f"- Execution mode: `synthetic_observe_only`",
        f"- Topology: `{document['topology']['name']}` (isolation: `{document['topology']['isolation']}`)",
        f"- Bounds: max {GLOBAL_MAX_EVENTS_PER_SCENARIO} events/scenario, {GLOBAL_MAX_RATE_PER_SEC} events/sec, {GLOBAL_MAX_SCENARIOS} scenarios",
        "",
        "## Expected decision matrix",
        "",
        "| Scenario | Kind | Rule | Layer | Severity | Config action | Canonical action | PEP | WFP | Cleanup |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for s in scenarios:
        d = s["expected_decision"]
        lines.append(
            f"| `{s['scenario_id']}` | `{s['kind']}` | `{s['rule_id']}` | `{s['layer']}` | "
            f"`{d['severity']}` | `{d['configured_action']}` | `{d['canonical_action']}` | "
            f"`{d['pep_authorization']}` | `{d['wfp_result']}` | `{s['cleanup_method']}` |"
        )
    lines += [
        "",
        "## Forbidden categories",
        "",
        "The lab must never contain: " + ", ".join(f"`{c}`" for c in FORBIDDEN_CATEGORIES) + ".",
        "",
        "## Acceptance",
        "",
        "Each scenario must produce a matched rule, its severity and action, deterministic",
        "event/request identifiers, a PEP decision (or an explicit unavailable), a forensic",
        "record, and a cleanup/rollback result. `WFP_RESULT` is `UNAVAILABLE_UNTIL_HOST_VERIFIED`",
        "until a test-signed host with the AEGIS WFP driver proves the host effect; the lab never",
        "claims a block it did not observe.",
        "",
    ]
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"generated {OUT_JSON}")
    print(f"generated {OUT_MD}")
    print(f"scenarios={len(scenarios)} active=false prevention_gate=closed")


if __name__ == "__main__":
    main()
