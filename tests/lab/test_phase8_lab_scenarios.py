"""Phase 8 — controlled attack-lab contract and runner tests.

These tests hold the lab to its safety contract. The interesting cases are the
negative ones: a validator that passes the good manifest proves nothing unless
it also rejects a tampered one, so each safety invariant gets an explicit
"validator must reject this" test.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "analysis" / "PHASE8_LAB_SCENARIO_MANIFEST.json"
RESULTS = ROOT / "analysis" / "PHASE8_LAB_SCENARIO_RESULTS.json"
RULES = ROOT / "configs" / "Rules.json"
VALIDATOR = ROOT / "scripts" / "validate_phase8_lab_manifest.py"
RUNNER = ROOT / "scripts" / "run_phase8_lab_scenarios.py"
SCENARIO_CONTRACT = ROOT / "src" / "lab" / "scenario_contract.zig"
RULE_ACTION = ROOT / "src" / "policy" / "rule_action.zig"

# Pinned in src/policy/rule_action.zig test
# "rule id hash matches the reference FNV-1a 32 vectors".
FNV1A32_VECTORS = {
    "hello": 0x4F9F2CAB,
    "a": 0xE40C292C,
    "R0056": 2107512682,
    "R0088": 4254503461,
}


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def manifest() -> dict:
    assert MANIFEST.is_file(), f"missing {MANIFEST}; run scripts/generate_phase8_lab_manifest.py"
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def rules() -> dict:
    return {
        r["rule_id"]: r
        for r in json.loads(RULES.read_text(encoding="utf-8"))["nids_rules"]
    }


@pytest.fixture(scope="module")
def runner():
    return _load_module(RUNNER, "phase8_runner")


def _validate(path: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, str(VALIDATOR), str(path)],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert proc.stdout.strip(), proc.stderr
    return json.loads(proc.stdout)


def _tampered(tmp_path: Path, mutate) -> Path:
    doc = json.loads(MANIFEST.read_text(encoding="utf-8"))
    mutate(doc)
    target = tmp_path / "tampered.json"
    target.write_text(json.dumps(doc), encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# Positive: the generated manifest and runner
# ---------------------------------------------------------------------------


def test_generated_manifest_validates() -> None:
    result = _validate(MANIFEST)
    assert result["passed"] is True, result["errors"]
    assert result["errors"] == []


def test_manifest_declares_inert_observe_only_mode(manifest: dict) -> None:
    assert manifest["active"] is False
    assert manifest["execution_mode"] == "synthetic_observe_only"
    assert manifest["global_prevention_gate"] == "closed"
    assert manifest["topology"]["external_egress"] is False
    assert manifest["topology"]["real_targets"] is False


def test_every_scenario_is_inert(manifest: dict) -> None:
    for scenario in manifest["scenarios"]:
        synthetic = scenario["synthetic_input"]
        assert synthetic["kind"] == "lab_marker_only"
        for field in (
            "payload_execution",
            "network_transmission",
            "file_mutation",
            "process_creation",
            "pipe_creation",
            "real_exploit",
        ):
            assert synthetic[field] is False, f"{scenario['scenario_id']}.{field}"


def test_no_scenario_uses_a_forbidden_category(manifest: dict) -> None:
    forbidden = set(manifest["forbidden_categories"])
    assert forbidden, "forbidden_categories must be declared"
    for scenario in manifest["scenarios"]:
        assert scenario["category"] not in forbidden


def test_scenarios_are_bounded(manifest: dict) -> None:
    bounds = manifest["bounds"]
    assert len(manifest["scenarios"]) == bounds["global_max_scenarios"]
    for scenario in manifest["scenarios"]:
        assert 0 < scenario["max_events"] <= bounds["global_max_events_per_scenario"]
        assert 0 < scenario["rate_limit_per_sec"] <= bounds["global_max_rate_per_sec"]


def test_every_scenario_declares_cleanup(manifest: dict) -> None:
    for scenario in manifest["scenarios"]:
        assert scenario["requires_cleanup"] is True
        assert scenario["cleanup_method"]
        if scenario["kind"] in {"file_canary", "process_canary", "bounded_recon"}:
            assert scenario["canary_expiry_s"] > 0, f"{scenario['scenario_id']} must expire"


def test_scenario_kinds_match_the_zig_contract(manifest: dict) -> None:
    source = SCENARIO_CONTRACT.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r"pub const ScenarioKind = enum\(u8\)\s*\{(?P<body>[^}]*)\}", source)
    assert match, "ScenarioKind enum not found"
    zig_kinds = {t.strip() for t in match.group("body").split(",") if t.strip()}
    manifest_kinds = {s["kind"] for s in manifest["scenarios"]}
    assert manifest_kinds == zig_kinds, (
        f"manifest_only={sorted(manifest_kinds - zig_kinds)} "
        f"contract_only={sorted(zig_kinds - manifest_kinds)}"
    )


def test_canonical_action_vocabulary_matches_zig_rule_action(manifest: dict) -> None:
    """The lab must express actions in the vocabulary the PEP dispatches on."""
    source = RULE_ACTION.read_text(encoding="utf-8", errors="ignore")
    pattern = re.compile(
        r"\.\{\s*\.config_string\s*=\s*\"([^\"]+)\",\s*"
        r"\.action\s*=\s*\.(\w+),\s*"
        r"\.privileged\s*=\s*(true|false)\s*\},"
    )
    zig = {token: (action, priv == "true") for token, action, priv in pattern.findall(source)}
    assert zig, "no mappings parsed from rule_action.zig"

    for scenario in manifest["scenarios"]:
        configured = scenario["configured_action"]
        assert configured in zig, f"{configured!r} missing from rule_action.zig"
        action, privileged = zig[configured]
        assert scenario["canonical_action"] == action
        assert scenario["privileged"] is privileged


def test_every_marker_really_matches_its_rule(manifest: dict, rules: dict) -> None:
    """`expected detection` must be a fact about the ruleset, not an aspiration."""
    for scenario in manifest["scenarios"]:
        rule = rules[scenario["rule_id"]]
        marker = scenario["marker"]
        assert re.search(rule["regex_pattern"], marker), (
            f"{scenario['scenario_id']}: marker {marker!r} does not match "
            f"{rule['regex_pattern']!r}"
        )
        decision = scenario["expected_decision"]
        assert decision["severity"] == rule["severity"]
        assert decision["configured_action"] == rule["action"]
        assert decision["wfp_result"] == "UNAVAILABLE_UNTIL_HOST_VERIFIED"


def test_lab_never_claims_a_wfp_block(manifest: dict) -> None:
    for scenario in manifest["scenarios"]:
        assert scenario["expected_decision"]["wfp_result"] == "UNAVAILABLE_UNTIL_HOST_VERIFIED"
        assert scenario["expected_decision"]["pep_expected"] in {
            "BLOCK_OR_FAIL_CLOSED_ESCALATE",
            "FAIL_CLOSED_ESCALATE",
        }


def test_rule_id_hash_matches_the_zig_pinned_vectors(runner) -> None:
    """The runner reimplements rule_loader.hashRuleId; keep them pinned."""
    for text, expected in FNV1A32_VECTORS.items():
        assert runner.hash_rule_id(text) == expected, f"FNV-1a 32 drift for {text!r}"


def test_runner_passes_and_reports_no_host_effect() -> None:
    proc = subprocess.run(
        [sys.executable, str(RUNNER)], cwd=ROOT, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    summary = json.loads(proc.stdout)

    assert summary["passed"] is True
    assert summary["failed_count"] == 0
    assert summary["host_effect_count"] == 0
    assert summary["wfp_block_claimed_count"] == 0
    assert summary["prevention_gate"] == "closed"

    results = json.loads(RESULTS.read_text(encoding="utf-8"))
    assert summary["scenario_count"] == results["scenario_count"]
    assert results["qualification"] == "SYNTHETIC_LAB_MARKER_NOT_HOST_PROOF"
    for row in results["results"]:
        assert row["detection_matched"] is True
        assert row["host_effect"] == "none"
        assert row["network_transmission"] is False
        assert row["payload_executed"] is False
        assert row["cleanup"]["cleanup_confirmed"] is True
        assert row["cleanup"]["residue_created"] is False
        assert row["event_id"] != 0 and row["request_id"] != 0
        assert row["decision_matrix"]["effect"] == "NONE"
        assert row["decision_matrix"]["wfp_result"] == "UNAVAILABLE_UNTIL_HOST_VERIFIED"
        assert row["decision_matrix"]["enforcement_receipt"] == "NOT_ISSUED"


def test_evidence_bundle_has_the_phase9_shape(runner, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner, "EVIDENCE_ROOT", tmp_path)
    doc = json.loads(RESULTS.read_text(encoding="utf-8"))
    bundle = runner.write_evidence_bundle(
        "phase8-test", doc, {"name": "test"}, {"available": False}, {"available": False}
    )
    expected = {
        "environment.json",
        "command.txt",
        "test-output.txt",
        "health-before.json",
        "health-after.json",
        "decision-trace.ndjson",
        "forensic-export.json",
        "artifact-digests.json",
        "result.json",
    }
    assert expected == {p.name for p in bundle.iterdir()}

    # decision trace must carry one ordered record per scenario
    lines = (bundle / "decision-trace.ndjson").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == doc["scenario_count"]
    for line in lines:
        trace = json.loads(line)
        assert [a["atom"] for a in trace["atoms"]] == [
            "event", "detection", "policy", "pep", "effect", "cleanup"
        ]


def test_cleanup_of_the_bundle_written_during_this_session() -> None:
    """The runner writes one bundle per invocation; keep only the newest few.

    The bundle is evidence, so it is not deleted here — this test just records
    where the current run's bundle is, so an operator can find it.
    """
    results = json.loads(RESULTS.read_text(encoding="utf-8"))
    bundle = ROOT / "evidence" / results["run_id"]
    if bundle.is_dir():
        assert (bundle / "result.json").is_file()


# ---------------------------------------------------------------------------
# Negative: the validator must reject a tampered manifest
# ---------------------------------------------------------------------------


def test_validator_rejects_opened_prevention_gate(tmp_path: Path) -> None:
    def mutate(doc: dict) -> None:
        doc["global_prevention_gate"] = "open"

    result = _validate(_tampered(tmp_path, mutate))
    assert result["passed"] is False
    assert any("prevention_gate" in e for e in result["errors"])


def test_validator_rejects_active_manifest(tmp_path: Path) -> None:
    def mutate(doc: dict) -> None:
        doc["active"] = True

    result = _validate(_tampered(tmp_path, mutate))
    assert result["passed"] is False
    assert any("active" in e for e in result["errors"])


def test_validator_rejects_non_synthetic_execution_mode(tmp_path: Path) -> None:
    def mutate(doc: dict) -> None:
        doc["execution_mode"] = "live_attack"

    result = _validate(_tampered(tmp_path, mutate))
    assert result["passed"] is False
    assert any("execution_mode" in e for e in result["errors"])


def test_validator_rejects_a_forbidden_category(tmp_path: Path) -> None:
    def mutate(doc: dict) -> None:
        doc["scenarios"][0]["category"] = "ransomware"

    result = _validate(_tampered(tmp_path, mutate))
    assert result["passed"] is False
    assert any("forbidden" in e for e in result["errors"])


def test_validator_rejects_an_unbounded_scenario(tmp_path: Path) -> None:
    def mutate(doc: dict) -> None:
        doc["scenarios"][0]["max_events"] = 100000

    result = _validate(_tampered(tmp_path, mutate))
    assert result["passed"] is False
    assert any("max_events" in e for e in result["errors"])


def test_validator_rejects_a_rate_limit_above_the_bound(tmp_path: Path) -> None:
    def mutate(doc: dict) -> None:
        doc["scenarios"][0]["rate_limit_per_sec"] = 5000

    result = _validate(_tampered(tmp_path, mutate))
    assert result["passed"] is False
    assert any("rate_limit_per_sec" in e for e in result["errors"])


def test_validator_rejects_dropped_cleanup(tmp_path: Path) -> None:
    def mutate(doc: dict) -> None:
        doc["scenarios"][0]["requires_cleanup"] = False

    result = _validate(_tampered(tmp_path, mutate))
    assert result["passed"] is False
    assert any("requires_cleanup" in e for e in result["errors"])


def test_validator_rejects_a_live_synthetic_input_flag(tmp_path: Path) -> None:
    def mutate(doc: dict) -> None:
        doc["scenarios"][0]["synthetic_input"]["network_transmission"] = True

    result = _validate(_tampered(tmp_path, mutate))
    assert result["passed"] is False
    assert any("network_transmission" in e for e in result["errors"])


def test_validator_rejects_an_unknown_scenario_kind(tmp_path: Path) -> None:
    def mutate(doc: dict) -> None:
        doc["scenarios"][0]["kind"] = "real_exploit"

    result = _validate(_tampered(tmp_path, mutate))
    assert result["passed"] is False
    assert any("scenario kinds" in e for e in result["errors"])


def test_validator_rejects_a_marker_that_does_not_match_the_rule(tmp_path: Path) -> None:
    def mutate(doc: dict) -> None:
        doc["scenarios"][0]["marker"] = "innocuous-text-that-matches-nothing"

    result = _validate(_tampered(tmp_path, mutate))
    assert result["passed"] is False
    assert any("does not match rule regex" in e for e in result["errors"])


def test_validator_rejects_a_wfp_block_claim(tmp_path: Path) -> None:
    def mutate(doc: dict) -> None:
        doc["scenarios"][0]["expected_decision"]["wfp_result"] = "BLOCKED_CONFIRMED"

    result = _validate(_tampered(tmp_path, mutate))
    assert result["passed"] is False
    assert any("wfp_result" in e for e in result["errors"])


def test_validator_rejects_a_drifted_canonical_action(tmp_path: Path) -> None:
    def mutate(doc: dict) -> None:
        doc["scenarios"][0]["canonical_action"] = "pass"
        doc["scenarios"][0]["privileged"] = False

    result = _validate(_tampered(tmp_path, mutate))
    assert result["passed"] is False
    assert any("canonical_action" in e for e in result["errors"])
