"""CONTRACT-FIXTURES-001: every contracts/fixtures sample must be validated.

The 13 fixture files under contracts/fixtures/ had no reader and no validator
anywhere in the repository, so they drifted from the contracts they claim to
sample (the detection fixture carried a severity the canonical wire space does
not define and a rule id no tier computes).

This module is the fixture gate. Each fixture is checked against the live
contract it belongs to: wire sizes, control protocol commands, lifecycle
states, the receipt vocabulary, the rule-id hash space and the project's own
conservation/observe-only invariants. The file list is asserted explicitly, so
a new fixture cannot be added without a validator.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "contracts" / "fixtures"
CANONICAL_RULES = REPO_ROOT / "configs" / "Rules.json"

CANONICAL_WIRE_BYTES = 109
IPC_WIRE_BYTES = 96
CONTROL_PROTOCOL_VERSION = 2
VALID_LIFECYCLE_STATES = ("STOPPED", "STARTING", "READY", "RUNNING", "DEGRADED", "FAILED")
CANONICAL_RULE_SEVERITY = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
RECEIPT_STATUS_NAMES = ("pending", "enforced", "failed", "unavailable", "rolled_back", "simulated")
WIRE_STATUS = {
    "pending": 0,
    "enforced": 1,
    "failed": 2,
    "unavailable": 2,
    "rolled_back": 3,
    "simulated": 0,
}

EXPECTED_FIXTURES = (
    "abi/event_boundaries.json",
    "adapters/degraded_etw.json",
    "control/runtime_health_request.json",
    "control/runtime_health_response.json",
    "data_plane/ingress_counters.json",
    "detection/signature_match.json",
    "enforcement/wfp_receipt.json",
    "health/degraded_core.json",
    "lab/scenario_result.json",
    "operator/recovery_result.json",
    "policy/active_policy.json",
    "release/bundle_manifest.json",
    "replay/observe_only.json",
)


def load_fixture(relative: str) -> dict:
    path = FIXTURES / relative
    assert path.exists(), f"fixture {relative} is missing"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict), f"{relative} must be a JSON object"
    return document


def fnv1a32(value: str) -> int:
    digest = 0x811C9DC5
    for byte in value.encode("utf-8"):
        digest ^= byte
        digest = (digest * 0x01000193) & 0xFFFFFFFF
    return digest


# ── the fixture set itself ─────────────────────────────────────────────────

def test_every_fixture_has_a_validator():
    present = sorted(
        str(path.relative_to(FIXTURES)).replace("\\", "/")
        for path in FIXTURES.rglob("*.json")
    )
    assert present == sorted(EXPECTED_FIXTURES), (
        "the validated fixture list must match the files on disk; add a validator "
        "for any new fixture"
    )


def test_fixtures_are_not_placeholders():
    for relative in EXPECTED_FIXTURES:
        text = (FIXTURES / relative).read_text(encoding="utf-8")
        assert text.strip(), relative
        for marker in ("TODO", "FIXME", "<placeholder>", "CHANGEME"):
            assert marker not in text, f"{relative} still contains {marker}"


def test_fixture_modules_agree_with_the_live_contracts():
    """The values the fixtures assert must match the contracts in the tree."""
    event = (REPO_ROOT / "src" / "contract" / "event.zig").read_text(encoding="utf-8")
    assert f"pub const EVENT_SIZE: usize = {IPC_WIRE_BYTES};" in event
    protocol = (REPO_ROOT / "src" / "control" / "protocol.zig").read_text(encoding="utf-8")
    assert f"pub const CONTROL_PROTOCOL_VERSION: u16 = {CONTROL_PROTOCOL_VERSION};" in protocol
    assert f'"wire_bytes": {CANONICAL_WIRE_BYTES}' in (FIXTURES / "abi/event_boundaries.json").read_text(
        encoding="utf-8"
    )
    assert f'"wire_bytes": {IPC_WIRE_BYTES}' in (FIXTURES / "abi/event_boundaries.json").read_text(
        encoding="utf-8"
    )


# ── per-fixture contracts ──────────────────────────────────────────────────

def test_abi_event_boundaries_declares_frozen_wire_sizes():
    document = load_fixture("abi/event_boundaries.json")
    boundaries = {item["name"]: item for item in document["boundaries"]}
    assert boundaries["canonical_event_v1"]["wire_bytes"] == CANONICAL_WIRE_BYTES
    assert boundaries["ipc_event_v5_internal"]["wire_bytes"] == IPC_WIRE_BYTES
    assert "not interchangeable" in document["rule"]


def test_control_health_request_uses_a_real_protocol_command():
    document = load_fixture("control/runtime_health_request.json")
    assert document["protocol_version"] == CONTROL_PROTOCOL_VERSION
    assert document["caller_role"] in {"read", "privileged"}
    protocol = (REPO_ROOT / "src" / "control" / "protocol.zig").read_text(encoding="utf-8")
    assert f'.name = "{document["command"]}"' in protocol, (
        f"{document['command']} is not a control protocol command"
    )
    # The retired legacy HEALTH op must never be the fixture's command.
    assert document["command"] != "HEALTH"


def test_control_health_response_carries_an_honest_state():
    document = load_fixture("control/runtime_health_response.json")
    assert document["ok"] is True and document["code"] == "OK"
    assert isinstance(document["data"], dict)
    assert document["data"]["runtime_state"] in VALID_LIFECYCLE_STATES
    assert document["data"]["component"]


def test_etw_adapter_fixture_names_its_unavailability():
    document = load_fixture("adapters/degraded_etw.json")
    assert document["state"] == "degraded"
    assert document["error_code"], "a degraded adapter must name its error"
    assert document["capability_mask"] == 0
    assert document["last_heartbeat_ms"] == 0


def test_ingress_counters_conserve_frames():
    document = load_fixture("data_plane/ingress_counters.json")
    counters = document["counters"]
    assert counters["frames_read"] - counters["frames_rejected"] == counters["frames_submitted"]
    accounted = counters["events_processed"] + counters["events_dropped"] + counters["duplicate_ids"]
    assert counters["frames_submitted"] == accounted
    assert document["conservation_gap"] == 0
    assert document["conservation_gap"] == counters["frames_submitted"] - accounted


def test_signature_match_fixture_uses_the_canonical_rule_space():
    document = load_fixture("detection/signature_match.json")
    rules = {rule["rule_id"]: rule for rule in json.loads(CANONICAL_RULES.read_text(encoding="utf-8"))["nids_rules"]}
    rule = rules[document["rule_key"]]
    assert document["rule_id"] == fnv1a32(document["rule_key"]), (
        "rule_id must be the FNV-1a of the rule key, the only rule-id space any tier uses"
    )
    assert document["severity"] == CANONICAL_RULE_SEVERITY[rule["severity"]], (
        "severity must be the canonical wire ordinal (0=Low,1=Medium,2=High,3=Critical)"
    )
    assert document["detector"] in {"signature", "anomaly", "correlation"}
    assert document["matched"] is True and document["reason"]


def test_wfp_receipt_fixture_cannot_claim_an_unproven_host_effect():
    document = load_fixture("enforcement/wfp_receipt.json")
    assert document["status"] in RECEIPT_STATUS_NAMES
    assert WIRE_STATUS[document["status"]] in (0, 1, 2, 3)
    assert document["decision"] in {"allow", "alert", "block", "quarantine", "rate_limit", "log_only"}
    if document["host_effect_confirmed"]:
        assert document["provider"], "a confirmed host effect must name its provider"
        assert document["filter_id"], "a confirmed host effect must name the installed filter"
        assert document["status"] == "enforced"
    assert document["status"] != "enforced" or document["host_effect_confirmed"]


def test_degraded_core_fixture_never_degrades_silently():
    document = load_fixture("health/degraded_core.json")
    assert document["state"] == "DEGRADED"
    assert document["runtime_state"] in VALID_LIFECYCLE_STATES
    assert document["degraded"] is True
    assert document["availability_error"], "a degraded core must name why"
    assert document["runtime_available"] is True
    assert isinstance(document["workers"], dict) and isinstance(document["data_plane"], dict)


def test_lab_scenario_fixture_proves_its_own_cleanup():
    document = load_fixture("lab/scenario_result.json")
    assert document["status"] == "cleaned"
    assert document["cleanup_confirmed"] is True, "a cleaned scenario must confirm cleanup"
    assert document["event_id"] != 0
    assert 0 <= document["matched_rule_id"] <= 0xFFFFFFFF


def test_operator_recovery_fixture_proves_its_postcondition():
    document = load_fixture("operator/recovery_result.json")
    assert document["outcome"] == "completed"
    assert document["postcondition_proven"] is True, "a completed operation must prove its postcondition"
    assert document["resulting_state"] in VALID_LIFECYCLE_STATES
    assert document["request_id"] != 0


def test_active_policy_fixture_is_a_digest_identified_policy():
    document = load_fixture("policy/active_policy.json")
    assert document["status"] == "active"
    assert document["digest"].startswith("sha256:")
    assert document["digest"] != "sha256:pending"
    assert document["signer"]
    assert document["policy_id"] != 0 and document["revision"] >= 1
    assert 0 <= document["expires_at_ms"]


def test_release_manifest_fixture_does_not_claim_unverified_evidence():
    document = load_fixture("release/bundle_manifest.json")
    pending = [a for a in document["artifacts"] if a["sha256"] == "sha256:pending"]
    if pending:
        assert document["signed"] is False, "an unsigned build must not claim a verified signature"
        assert all(a["sha256"].startswith("sha256:") for a in document["artifacts"])
    if document["signed"]:
        assert document["install_tested"] and document["rollback_tested"], (
            "a signed bundle must have been installed and rolled back in a test"
        )
        assert not pending, "a signed bundle must not ship placeholder artifact digests"
    assert re.fullmatch(r"[0-9a-f]{7,40}", document["source_commit"]), (
        "the manifest must name the source commit it was built from"
    )
    for artifact in document["artifacts"]:
        assert artifact["source_commit"] == document["source_commit"], (
            "every artifact must come from the manifest's source commit"
        )


def test_replay_fixture_is_observe_only():
    document = load_fixture("replay/observe_only.json")
    assert document["mode"] == "observe_only"
    assert document["allow_host_mutation"] is False
    assert document["expected_enforcement_attempts"] == 0
    assert document["source_digest"].startswith("sha256:")
