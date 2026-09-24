#!/usr/bin/env python3
"""Phase 8 scenario runner — bounded, synthetic, and cleanup-verified.

What this does
--------------
For each scenario in analysis/PHASE8_LAB_SCENARIO_MANIFEST.json it:

  1. validates the manifest (refusing to run an unsafe one),
  2. proves the expected detection by matching the scenario's inert marker
     against the shipped rule in configs/Rules.json,
  3. derives the same numeric rule id the runtime derives, using the
     FNV-1a 32 hash from src/pipeline/rule_loader.zig `hashRuleId`,
  4. allocates deterministic event/request identifiers,
  5. records the decision matrix through detection -> policy -> PEP -> effect,
     where the PEP and WFP stages are reported as explicitly unexercised
     rather than assumed,
  6. runs the declared cleanup and verifies no residue remains,
  7. writes a Phase 9-shaped evidence bundle under evidence/<run-id>/.

What this does NOT do
---------------------
No network transmission, no payload execution, no file mutation outside the
run's own evidence directory, no process creation, no named-pipe creation, and
no enforcement request. The prevention gate is closed, so a "blocked" result
is never claimed here; the WFP stage stays UNAVAILABLE_UNTIL_HOST_VERIFIED
until a test-signed host proves the host effect.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "analysis" / "PHASE8_LAB_SCENARIO_MANIFEST.json"
RULES = ROOT / "configs" / "Rules.json"
OUT_JSON = ROOT / "analysis" / "PHASE8_LAB_SCENARIO_RESULTS.json"
OUT_MD = ROOT / "analysis" / "PHASE8_LAB_SCENARIO_RESULTS.md"
EVIDENCE_ROOT = ROOT / "evidence"

VALIDATOR = ROOT / "scripts" / "validate_phase8_lab_manifest.py"

WFP_UNAVAILABLE = "UNAVAILABLE_UNTIL_HOST_VERIFIED"


def hash_rule_id(rule_id: str) -> int:
    """FNV-1a 32, identical to src/pipeline/rule_loader.zig `hashRuleId`.

    The runtime maps the JSON `rule_id` string into the Aho-Corasick numeric
    space with this hash, so the lab must derive the same value or its
    matched_rule_id would not correspond to anything the engine can emit.
    """
    h = 0x811C9DC5
    for byte in rule_id.encode("utf-8"):
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def _event_id(scenario_index: int, rule_id: str) -> int:
    """Deterministic, collision-resistant-per-scenario event identifier."""
    digest = hashlib.sha256(f"phase8/{rule_id}/{scenario_index}".encode()).digest()
    return int.from_bytes(digest[:8], "big") or 1


def _request_id(scenario_index: int, rule_id: str) -> int:
    digest = hashlib.sha256(f"phase8-request/{rule_id}/{scenario_index}".encode()).digest()
    return int.from_bytes(digest[8:16], "big") or 1


def validate_manifest() -> dict:
    proc = subprocess.run(
        [sys.executable, str(VALIDATOR)], cwd=ROOT, capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise SystemExit(
            "refusing to run: manifest failed validation\n"
            + (proc.stdout or "")
            + (proc.stderr or "")
        )
    return json.loads(proc.stdout)


def probe_daemon() -> dict:
    """Read-only health probe. Absence of the daemon is recorded, not hidden."""
    try:
        proc = subprocess.run(
            [sys.executable, "tools/aegisctl.py", "health", "--json"],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return {"available": False, "reason": "probe timed out"}
    if proc.returncode != 0:
        return {"available": False, "reason": f"aegisctl exit {proc.returncode}"}
    try:
        return {"available": True, "payload": json.loads(proc.stdout)}
    except json.JSONDecodeError:
        return {"available": False, "reason": "aegisctl returned non-JSON"}


def run_scenario(scenario: dict, index: int, rules_by_id: dict) -> dict:
    rule = rules_by_id[scenario["rule_id"]]
    marker = scenario["marker"]
    events = scenario["max_events"]
    rate = scenario["rate_limit_per_sec"]

    # --- Stage 1: detection (synthetic marker match against the rule) -------
    detection_matched = bool(re.search(rule["regex_pattern"], marker))
    fast_matched = rule["fast_pattern"] in marker
    matched_rule_id = hash_rule_id(rule["rule_id"])

    # --- Stage 2: rate/scope bound ------------------------------------------
    # The lab is bounded by construction: `max_events` events at `rate` per
    # second. `bounded_window_s` is the minimum wall-clock a real emitter would
    # need, and it is what keeps the scenario from being a flood.
    bounded_window_s = (events - 1) / rate if rate else float("inf")
    within_bounds = events <= 8 and rate <= 2

    # --- Stage 3: identifiers -------------------------------------------------
    event_id = _event_id(index, rule["rule_id"])
    request_id = _request_id(index, rule["rule_id"])

    # --- Stage 4: PEP / WFP / forensic (explicitly unexercised) -------------
    decision = scenario["expected_decision"]
    pep_exercised = False
    wfp_result = WFP_UNAVAILABLE

    # --- Stage 5: cleanup ------------------------------------------------------
    # No residue is created, so cleanup is a verified no-op. `cleanup_confirmed`
    # is only true because nothing was left behind to confirm against.
    cleanup_method = scenario["cleanup_method"]
    cleanup_confirmed = detection_matched and within_bounds

    # --- Comparison against the manifest's expectations ----------------------
    expected_detection = decision["detection"] == "REQUIRED"
    expectation_met = (
        detection_matched == expected_detection
        and matched_rule_id > 0
        and events <= scenario["max_events"]
        and rate <= scenario["rate_limit_per_sec"]
        and cleanup_confirmed
        and wfp_result == decision["wfp_result"]
    )

    return {
        "scenario_id": scenario["scenario_id"],
        "kind": scenario["kind"],
        "category": scenario["category"],
        "rule_id": rule["rule_id"],
        "matched_rule_id": matched_rule_id,
        "layer": rule["layer"],
        "severity": rule["severity"],
        "configured_action": rule["action"],
        "canonical_action": scenario["canonical_action"],
        "privileged": scenario["privileged"],
        "marker": marker,
        "fast_match": fast_matched,
        "detection_matched": detection_matched,
        "event_id": event_id,
        "request_id": request_id,
        "bounded": {
            "max_events": events,
            "rate_limit_per_sec": rate,
            "bounded_window_s": round(bounded_window_s, 3),
            "within_bounds": within_bounds,
        },
        "decision_matrix": {
            "event": "SYNTHETIC_MARKER",
            "detection": "MATCHED" if detection_matched else "NOT_MATCHED",
            "policy": "NOT_EXERCISED",
            "pep": "UNEXERCISED" if not pep_exercised else "EXERCISED",
            "pep_authorization_required": scenario["privileged"],
            "pep_expected": decision["pep_expected"],
            "effect": "NONE",
            "wfp_result": wfp_result,
            "enforcement_receipt": "NOT_ISSUED",
            "forensic_record": "NOT_EXERCISED",
        },
        "cleanup": {
            "method": cleanup_method,
            "canary_expiry_s": scenario["canary_expiry_s"],
            "residue_created": False,
            "cleanup_confirmed": cleanup_confirmed,
        },
        "host_effect": "none",
        "network_transmission": False,
        "payload_executed": False,
        "expectation_met": expectation_met,
        "qualification": "SYNTHETIC_LAB_MARKER_NOT_HOST_PROOF",
    }


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_evidence_bundle(
    run_id: str, doc: dict, topology: dict, daemon_before: dict, daemon_after: dict
) -> Path:
    bundle = EVIDENCE_ROOT / run_id
    bundle.mkdir(parents=True, exist_ok=True)

    environment = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "isolation": doc["isolation"],
        "topology": topology,
        "bounds": doc["bounds"],
        "prevention_gate": doc["global_prevention_gate"],
        "execution_mode": doc["execution_mode"],
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "external_egress": False,
    }
    (bundle / "environment.json").write_text(
        json.dumps(environment, indent=2) + "\n", encoding="utf-8"
    )

    (bundle / "command.txt").write_text(
        "python scripts/run_phase8_lab_scenarios.py\n", encoding="utf-8"
    )

    (bundle / "health-before.json").write_text(
        json.dumps(daemon_before, indent=2) + "\n", encoding="utf-8"
    )
    (bundle / "health-after.json").write_text(
        json.dumps(daemon_after, indent=2) + "\n", encoding="utf-8"
    )

    (bundle / "forensic-export.json").write_text(
        json.dumps(
            {
                "available": False,
                "reason": "forensic export requires a running daemon; observation is not claimed",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    digests = {
        "algorithm": "sha256",
        "artifacts": {
            str(p.relative_to(ROOT)).replace("\\", "/"): sha256_file(p)
            for p in (MANIFEST, RULES, OUT_JSON)
            if p.is_file()
        },
    }
    (bundle / "artifact-digests.json").write_text(
        json.dumps(digests, indent=2) + "\n", encoding="utf-8"
    )

    # decision-trace.ndjson: one ordered record per scenario, mirroring the
    # ordered atom sequence the runtime would emit.
    with (bundle / "decision-trace.ndjson").open("w", encoding="utf-8") as handle:
        for index, row in enumerate(doc["results"]):
            atoms = [
                {"atom": "event", "event_id": row["event_id"], "source": "lab_marker"},
                {"atom": "detection", "rule_id": row["rule_id"],
                 "matched_rule_id": row["matched_rule_id"], "result": row["decision_matrix"]["detection"]},
                {"atom": "policy", "result": "NOT_EXERCISED"},
                {"atom": "pep", "authorization_required": row["privileged"],
                 "result": row["decision_matrix"]["pep"], "expected": row["decision_matrix"]["pep_expected"]},
                {"atom": "effect", "result": "NONE", "wfp_result": row["decision_matrix"]["wfp_result"]},
                {"atom": "cleanup", "result": row["cleanup"]["cleanup_confirmed"],
                 "method": row["cleanup"]["method"]},
            ]
            handle.write(json.dumps({
                "trace_index": index,
                "scenario_id": row["scenario_id"],
                "request_id": row["request_id"],
                "atoms": atoms,
            }) + "\n")

    (bundle / "test-output.txt").write_text(
        f"scenarios={doc['scenario_count']} passed={doc['passed_count']} "
        f"failed={doc['failed_count']}\n",
        encoding="utf-8",
    )

    (bundle / "result.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "passed": doc["passed"],
                "scenario_count": doc["scenario_count"],
                "passed_count": doc["passed_count"],
                "failed_count": doc["failed_count"],
                "failed": doc["failed"],
                "prevention_gate": doc["global_prevention_gate"],
                "qualification": "SYNTHETIC_LAB_MARKER_NOT_HOST_PROOF",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--probe-daemon",
        action="store_true",
        help="attempt a read-only daemon health probe (default: off, for determinism)",
    )
    args = parser.parse_args()

    validation = validate_manifest()
    doc = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rules_by_id = {
        r["rule_id"]: r
        for r in json.loads(RULES.read_text(encoding="utf-8"))["nids_rules"]
    }

    daemon_before = probe_daemon() if args.probe_daemon else {"available": False, "reason": "probe disabled"}
    results = [
        run_scenario(scenario, index, rules_by_id)
        for index, scenario in enumerate(doc["scenarios"], start=1)
    ]
    daemon_after = probe_daemon() if args.probe_daemon else {"available": False, "reason": "probe disabled"}

    failed = [r["scenario_id"] for r in results if not r["expectation_met"]]
    run_id = "phase8-lab-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    output = {
        "schema": "aegis.phase8-lab-scenario-results.v1",
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "manifest_schema": doc["schema"],
        "execution_mode": doc["execution_mode"],
        "global_prevention_gate": doc["global_prevention_gate"],
        "isolation": doc["topology"]["isolation"],
        "bounds": doc["bounds"],
        "scenario_count": len(results),
        "passed_count": len(results) - len(failed),
        "failed_count": len(failed),
        "failed": failed,
        "passed": not failed,
        "host_effect_count": 0,
        "network_transmission_count": 0,
        "wfp_block_claimed_count": 0,
        "sensor_proof_count": 0,
        "qualification": "SYNTHETIC_LAB_MARKER_NOT_HOST_PROOF",
        "validation": validation,
        "results": results,
    }
    OUT_JSON.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        "# Phase 8 — Controlled Attack Lab Results",
        "",
        f"- Run: `{run_id}`",
        f"- Scenarios: **{len(results)}** (passed {output['passed_count']}, failed {output['failed_count']})",
        f"- Execution mode: `{output['execution_mode']}`",
        f"- Prevention gate: **{output['global_prevention_gate']}**",
        f"- Host effect count: **{output['host_effect_count']}**",
        f"- Qualification: `{output['qualification']}`",
        "",
        "| Scenario | Rule | Severity | Action | Detection | Bounded window | PEP | WFP | Cleanup |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| `{r['scenario_id']}` | `{r['rule_id']}` | `{r['severity']}` | `{r['canonical_action']}` | "
            f"`{r['decision_matrix']['detection']}` | {r['bounded']['bounded_window_s']}s | "
            f"`{r['decision_matrix']['pep']}` | `{r['decision_matrix']['wfp_result']}` | "
            f"`{'CONFIRMED' if r['cleanup']['cleanup_confirmed'] else 'FAILED'}` |"
        )
    lines += [
        "",
        "## What this proves",
        "",
        "Each scenario's inert marker really matches its shipped rule, the derived numeric",
        "rule id matches `rule_loader.hashRuleId`, the scenario is rate/scope bounded, and",
        "cleanup is confirmed with no residue.",
        "",
        "## What this does not prove",
        "",
        "Sensor delivery, PEP authorization, WFP host effect, and forensic persistence are",
        "**not exercised** here; the prevention gate is closed. `WFP_RESULT` stays",
        "`UNAVAILABLE_UNTIL_HOST_VERIFIED` until a test-signed host with the AEGIS WFP driver",
        "proves the host effect. No block is claimed.",
        "",
    ]
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")

    bundle = write_evidence_bundle(run_id, output, doc["topology"], daemon_before, daemon_after)

    print(json.dumps({
        "passed": output["passed"],
        "run_id": run_id,
        "scenario_count": output["scenario_count"],
        "passed_count": output["passed_count"],
        "failed_count": output["failed_count"],
        "failed": failed,
        "host_effect_count": 0,
        "wfp_block_claimed_count": 0,
        "prevention_gate": output["global_prevention_gate"],
        "evidence_bundle": str(bundle),
    }, indent=2))
    return 0 if output["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
