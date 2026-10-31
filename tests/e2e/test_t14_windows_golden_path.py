"""T14: current-head IDS flow contract (source checks, not Windows E5 proof).

T14 pins the production detection-only path and its evidence boundaries. It
must not claim a supervised Windows E2E, kernel qualification, or production
WFP host effect based solely on source inspection or unit tests.
"""
from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _json(name: str) -> dict:
    return json.loads((REPO_ROOT / name).read_text(encoding="utf-8"))


def test_manifest_describes_detection_only_and_does_not_claim_windows_e5() -> None:
    manifest = _json("runtime_manifest.json")
    assert "detection-only" in manifest["notes"]["enforcement_mode"].lower()
    assert "permanently out of scope" in manifest["notes"]["enforcement_mode"].lower()
    assert "not_proven" in manifest["notes"]["host_verification_status"].lower()
    assert not any("wfp (windows enforcement)" in stage.lower() for stage in manifest["golden_path"])
    assert "replay" not in manifest["golden_path"]
    assert "replay" in manifest["verification_path"]


def test_production_flow_orders_detection_forensics_and_recording_receipt() -> None:
    flow_map = _json("FLOW_MAP.json")
    flow = next(item for item in flow_map["flows"] if item["id"] == "DATA-001")
    assert flow["status"] == "PRODUCTION_DETECTION_ONLY"
    names = [layer["name"] for layer in flow["layers"]]
    positions = {name: names.index(name) for name in (
        "Length-Prefixed Named-Pipe Transport",
        "Conditional Rust PEP Guard",
        "Forensic Record",
        "IDS Evidence Receipt",
    )}
    assert positions["Length-Prefixed Named-Pipe Transport"] < positions["Conditional Rust PEP Guard"]
    assert positions["Conditional Rust PEP Guard"] < positions["Forensic Record"] < positions["IDS Evidence Receipt"]
    assert any("host effects" in layer.get("note", "").lower() for layer in flow["layers"])


def test_go_nose_uses_a_length_prefixed_named_pipe_not_a_c_abi_call() -> None:
    writer = (REPO_ROOT / "nose/pipe_writer.go").read_text(encoding="utf-8")
    reader = (REPO_ROOT / "src/capture/nose_pipe_reader.zig").read_text(encoding="utf-8")
    flow_map = _json("FLOW_MAP.json")
    transport = next(item for item in flow_map["flows"] if item["id"] == "FFI-003")

    assert "aegis_nose" in writer
    assert "frame[0] = byte(ple)" in writer
    assert "writeAll(frame[:4+len(wire)])" in writer
    assert "CreateNamedPipeW" in reader and "readClientLoop" in reader
    assert transport["type"] == "transport_boundary"
    assert "not a C ABI" in transport["description"]


def test_ids_receipt_requires_accepted_forensic_record_and_hash_readback() -> None:
    processor = (REPO_ROOT / "src/pipeline/event_processor.zig").read_text(encoding="utf-8")
    append_at = processor.index("const forensic_seq = appendForensicRecord(")
    hash_at = processor.index("forensic_ring.recordHash(forensic_seq)")
    receipt_at = processor.index("ids_receipt.issue(")
    assert append_at < hash_at < receipt_at
    assert "This never represents a host effect" in processor


def test_python_brain_return_is_optional_and_reenters_as_advisory_event() -> None:
    daemon = (REPO_ROOT / "src/daemon.zig").read_text(encoding="utf-8")
    brain = (REPO_ROOT / "brain/windows_brain.py").read_text(encoding="utf-8")
    adapter = (REPO_ROOT / "src/core/nids_capture.zig").read_text(encoding="utf-8")
    event_contract = (REPO_ROOT / "src/contract/event.zig").read_text(encoding="utf-8")

    assert 'getEnvVarOwned(std.heap.page_allocator, "AEGIS_BRAIN")' in daemon
    assert 'SENSOR_PIPE_ENABLED = os.environ.get("AEGIS_SENSOR_PIPE", "0") == "1"' in brain
    assert '"source": "brain_tier2"' in brain
    assert "ev.source = .detection_brain;" in adapter
    assert "Advisory detection input" in event_contract
    assert "never a host-effect claim by itself" in event_contract


def test_prevention_and_xdr_routes_are_not_production_host_effect_capabilities() -> None:
    manifest = _json("runtime_manifest.json")
    modules = manifest["modules"]
    gate = (REPO_ROOT / "build.zig").read_text(encoding="utf-8")
    wfp = (REPO_ROOT / "src/policy/wfp_production.zig").read_text(encoding="utf-8")

    assert "lab-prevention-gate" in gate and "orelse false" in gate
    assert "return .unavailable;" in wfp
    for module in (
        "src/capture/npcap_capture.zig",
        "src/detection/proto_anomaly.zig",
        "src/xdr/xdr_incident_fabric.zig",
    ):
        assert modules[module]["status"] == "LAB"
        assert modules[module]["golden_path"] is False
    assert modules["src/policy/wfp_production.zig"]["golden_path"] is False
    assert any(item["id"] == "XDR-LAB-001" and item["status"] == "LAB_ONLY_NOT_RUNTIME_WIRED"
               for item in _json("FLOW_MAP.json")["flows"])
