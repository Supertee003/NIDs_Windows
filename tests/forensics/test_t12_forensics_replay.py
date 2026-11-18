"""T12: current-head forensic recording, IDS receipt, and separate replay path.

These tests pin source/map contracts only. They do not establish Windows E5,
production host-effect capability, or release-level forensic qualification.
"""
from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _json(name: str) -> dict:
    return json.loads((REPO_ROOT / name).read_text(encoding="utf-8"))


def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8", errors="ignore")


def test_production_golden_path_and_replay_verification_are_separate() -> None:
    manifest = _json("runtime_manifest.json")
    golden = manifest["golden_path"]
    verification = manifest["verification_path"]

    assert "forensics (immutable trace)" in golden
    assert "IDS Evidence Receipt (record-only; after forensic append and hash read-back)" in golden
    assert "replay" not in golden
    assert verification[0] == "forensics (immutable trace)"
    assert "integrity verify" in verification and "replay" in verification
    assert "not_proven" in manifest["notes"]["host_verification_status"].lower()
    for module in (
        "src/forensic/forensics_engine.zig",
        "src/forensic/replay_engine.zig",
        "src/tests/proofs/forensic_replay_proof.zig",
        "src/tests/integration/forensics_integration.zig",
        "src/forensic/replayable_security.zig",
    ):
        assert manifest["modules"][module]["golden_path"] is False


def test_event_processor_appends_forensics_before_issuing_recording_receipt() -> None:
    processor = _read("src/pipeline/event_processor.zig")
    append_at = processor.index("const forensic_seq = appendForensicRecord(")
    hash_at = processor.index("forensic_ring.recordHash(forensic_seq)")
    issue_at = processor.index("ids_receipt.issue(")
    log_at = processor.index("evidenceLog(ev,")

    assert append_at < hash_at < issue_at < log_at
    receipt = _read("src/forensic/ids_evidence_receipt.zig")
    assert "never proves a host effect" in receipt
    assert "contains no provider/filter/action fields" in receipt
    assert "pub fn issue(" in receipt


def test_runtime_forensic_ring_exposes_hash_chain_and_record_readback() -> None:
    source = _read("src/forensic/forensic_pipeline.zig")
    assert "pub const ForensicRing = struct" in source
    assert "pub fn verifyHashChain" in source
    assert "pub fn recordHash" in source
    assert "pub fn readRecord" in source
    assert "current_hash" in source and "prev_hash" in source


def test_replay_verifier_is_observation_only_by_default_and_not_event_hot_path() -> None:
    source = _read("src/forensic/replay_verifier.zig")
    assert "pub const ReplayVerifier = struct" in source
    assert "pub fn exportRecords" in source
    assert "pub fn verifyIntegrity" in source
    assert "observe_only = 0" in source
    assert "replay never executes live enforcement by default" in source

    flow_map = _json("FLOW_MAP.json")
    evidence = next(flow for flow in flow_map["flows"] if flow["id"] == "EVIDENCE-001")
    names = [layer["name"].lower() for layer in evidence["layers"]]
    assert any("replay" in name for name in names)
    data = next(flow for flow in flow_map["flows"] if flow["id"] == "DATA-001")
    assert all("replay" not in layer["name"].lower() for layer in data["layers"])
