#!/usr/bin/env python3
"""Validate the Phase 8 controlled attack-lab scenario manifest.

Fails closed on anything that would make the lab unsafe or untruthful:

  * the prevention gate must be closed and the mode synthetic/observe-only
  * forbidden categories (real malware, credential theft, ransomware, flood,
    exploit execution, exfiltration, privilege escalation) must be absent
  * every scenario must be bounded in event count and rate
  * every scenario must declare cleanup, and canary scenarios must expire
  * each scenario must reference a shipped rule whose severity/action match
  * each marker must actually match its rule's regex, so "expected detection"
    is a fact about the ruleset rather than an aspiration
  * the scenario-kind set must equal src/lab/scenario_contract.zig
  * the config-action vocabulary must equal src/policy/rule_action.zig

Cross-language checks are parsed from the Zig sources so the manifest cannot
drift away from the contracts it claims to implement.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "analysis" / "PHASE8_LAB_SCENARIO_MANIFEST.json"
RULES = ROOT / "configs" / "Rules.json"
SCENARIO_CONTRACT = ROOT / "src" / "lab" / "scenario_contract.zig"
RULE_ACTION = ROOT / "src" / "policy" / "rule_action.zig"

EXPECTED_SCHEMA = "aegis.phase8-lab-scenario-manifest.v1"

# Structural facts the runtime depends on, pinned here so neither side drifts.
REQUIRED_TOPOLOGY_EXTERNAL_EGRESS = False
REQUIRED_TOPOLOGY_REAL_TARGETS = False

FORBIDDEN_INPUT_TRUE_FIELDS = (
    "payload_execution",
    "network_transmission",
    "file_mutation",
    "process_creation",
    "pipe_creation",
    "real_exploit",
)

CANARY_KINDS = {"file_canary", "process_canary", "bounded_recon"}


def _zig_scenario_kinds() -> set[str]:
    source = SCENARIO_CONTRACT.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r"pub const ScenarioKind = enum\(u8\)\s*\{(?P<body>[^}]*)\}", source)
    if not match:
        raise SystemExit(f"ScenarioKind enum not found in {SCENARIO_CONTRACT}")
    return {tok.strip() for tok in match.group("body").split(",") if tok.strip()}


def _zig_rule_actions() -> dict[str, tuple[str, bool]]:
    source = RULE_ACTION.read_text(encoding="utf-8", errors="ignore")
    pattern = re.compile(
        r"\.\{\s*\.config_string\s*=\s*\"([^\"]+)\",\s*"
        r"\.action\s*=\s*\.(\w+),\s*"
        r"\.privileged\s*=\s*(true|false)\s*\},"
    )
    found: dict[str, tuple[str, bool]] = {}
    for token, action, privileged in pattern.findall(source):
        found[token] = (action, privileged == "true")
    if not found:
        raise SystemExit(f"no action mappings parsed from {RULE_ACTION}")
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the Phase 8 lab manifest")
    parser.add_argument(
        "path",
        nargs="?",
        default=str(MANIFEST),
        help="manifest to validate (defaults to the generated one)",
    )
    args = parser.parse_args()
    doc = json.loads(Path(args.path).read_text(encoding="utf-8"))
    rules_by_id = {
        r["rule_id"]: r
        for r in json.loads(RULES.read_text(encoding="utf-8"))["nids_rules"]
    }
    errors: list[str] = []

    # --- document-level safety invariants ---------------------------------
    if doc.get("schema") != EXPECTED_SCHEMA:
        errors.append(f"schema must be {EXPECTED_SCHEMA}")
    if doc.get("active") is not False:
        errors.append("manifest active must be false")
    if doc.get("execution_mode") != "synthetic_observe_only":
        errors.append("execution_mode must be synthetic_observe_only")
    if doc.get("global_prevention_gate") != "closed":
        errors.append("global_prevention_gate must be closed")

    topology = doc.get("topology", {})
    if topology.get("external_egress") is not REQUIRED_TOPOLOGY_EXTERNAL_EGRESS:
        errors.append("topology.external_egress must be false")
    if topology.get("real_targets") is not REQUIRED_TOPOLOGY_REAL_TARGETS:
        errors.append("topology.real_targets must be false")
    if not topology.get("isolation"):
        errors.append("topology.isolation must be declared")

    forbidden = set(doc.get("forbidden_categories", []))
    if not forbidden:
        errors.append("forbidden_categories must be declared")

    bounds = doc.get("bounds", {})
    max_events = bounds.get("global_max_events_per_scenario")
    max_rate = bounds.get("global_max_rate_per_sec")
    max_scenarios = bounds.get("global_max_scenarios")
    if not isinstance(max_events, int) or max_events <= 0:
        errors.append("bounds.global_max_events_per_scenario must be a positive int")
    if not isinstance(max_rate, int) or max_rate <= 0:
        errors.append("bounds.global_max_rate_per_sec must be a positive int")
    if not isinstance(max_scenarios, int) or max_scenarios <= 0:
        errors.append("bounds.global_max_scenarios must be a positive int")

    # --- cross-language: scenario kinds vs Zig contract -------------------
    zig_kinds = _zig_scenario_kinds()
    manifest_kinds = {s.get("kind") for s in doc.get("scenarios", [])}
    if manifest_kinds != zig_kinds:
        errors.append(
            "scenario kinds must equal src/lab/scenario_contract.zig: "
            f"manifest_only={sorted(manifest_kinds - zig_kinds)} "
            f"contract_only={sorted(zig_kinds - manifest_kinds)}"
        )

    # --- cross-language: config action vocabulary vs Zig ------------------
    zig_actions = _zig_rule_actions()
    for scenario in doc.get("scenarios", []):
        sid = scenario.get("scenario_id", "<missing>")
        configured = scenario.get("configured_action")
        canonical = scenario.get("canonical_action")
        privileged = scenario.get("privileged")

        if configured not in zig_actions:
            errors.append(f"{sid}: configured_action {configured!r} not in rule_action.zig")
        else:
            expected_action, expected_privileged = zig_actions[configured]
            if canonical != expected_action:
                errors.append(
                    f"{sid}: canonical_action {canonical!r} != rule_action.zig {expected_action!r}"
                )
            if privileged is not expected_privileged:
                errors.append(
                    f"{sid}: privileged {privileged!r} != rule_action.zig {expected_privileged!r}"
                )

        # --- bounds ------------------------------------------------------
        if not scenario.get("requires_cleanup"):
            errors.append(f"{sid}: requires_cleanup must be true")
        if not scenario.get("cleanup_method"):
            errors.append(f"{sid}: cleanup_method must be declared")
        events = scenario.get("max_events")
        rate = scenario.get("rate_limit_per_sec")
        if not isinstance(events, int) or events <= 0 or events > max_events:
            errors.append(f"{sid}: max_events must be 1..{max_events}")
        if not isinstance(rate, int) or rate <= 0 or rate > max_rate:
            errors.append(f"{sid}: rate_limit_per_sec must be 1..{max_rate}")
        if scenario.get("kind") in CANARY_KINDS and not scenario.get("canary_expiry_s", 0) > 0:
            errors.append(f"{sid}: {scenario.get('kind')} must declare canary_expiry_s > 0")

        # --- forbidden categories ----------------------------------------
        if scenario.get("category") in forbidden:
            errors.append(f"{sid}: category {scenario.get('category')!r} is forbidden")

        # --- inert input flags -------------------------------------------
        synthetic = scenario.get("synthetic_input", {})
        for field in FORBIDDEN_INPUT_TRUE_FIELDS:
            if synthetic.get(field) is not False:
                errors.append(f"{sid}: synthetic_input.{field} must be false")

        # --- detection expectation must be real --------------------------
        rule = rules_by_id.get(scenario.get("rule_id"))
        if rule is None:
            errors.append(f"{sid}: unknown rule_id {scenario.get('rule_id')!r}")
            continue
        decision = scenario.get("expected_decision", {})
        if decision.get("matched_rule_id") != rule["rule_id"]:
            errors.append(f"{sid}: expected_decision.matched_rule_id must be {rule['rule_id']}")
        if decision.get("severity") != rule["severity"]:
            errors.append(f"{sid}: severity must match rule ({rule['severity']})")
        if decision.get("configured_action") != rule["action"]:
            errors.append(f"{sid}: configured_action must match rule ({rule['action']})")
        if decision.get("wfp_result") != "UNAVAILABLE_UNTIL_HOST_VERIFIED":
            errors.append(
                f"{sid}: wfp_result must be UNAVAILABLE_UNTIL_HOST_VERIFIED until a "
                "test-signed host proves the host effect"
            )
        for required_field in ("event_id", "request_id"):
            if required_field in decision and decision[required_field] == 0:
                errors.append(f"{sid}: expected_decision.{required_field} must be non-zero")

        marker = scenario.get("marker", "")
        try:
            if not re.search(rule["regex_pattern"], marker):
                errors.append(
                    f"{sid}: marker {marker!r} does not match rule regex "
                    f"{rule['regex_pattern']!r}, so expected detection is not real"
                )
        except re.error as exc:
            errors.append(f"{sid}: rule regex is not compilable: {exc}")

    scenarios = doc.get("scenarios", [])
    if len(scenarios) != max_scenarios:
        errors.append(f"scenario count {len(scenarios)} != declared bound {max_scenarios}")
    ids = [s.get("scenario_id") for s in scenarios]
    if len(set(ids)) != len(ids):
        errors.append("scenario_id values must be unique")

    result = {
        "passed": not errors,
        "schema": doc.get("schema"),
        "scenario_count": len(scenarios),
        "execution_mode": doc.get("execution_mode"),
        "prevention_gate": doc.get("global_prevention_gate"),
        "errors": errors,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
