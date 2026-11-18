"""MAP-006: machine-readable runtime claims must match current source wiring.

These are source/map consistency checks only. They do not claim Windows E5,
production host-effect capability, or live XDR receipt/replay integration.
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _json(name: str) -> dict:
    return json.loads((REPO / name).read_text(encoding="utf-8"))


def _source_exists(path: str) -> bool:
    if any(token in path for token in ("*", "?", "[")):
        return any(REPO.glob(path))
    return (REPO / path).is_file()


def test_runtime_manifest_is_detection_only_and_does_not_claim_e5() -> None:
    manifest = _json("runtime_manifest.json")
    notes = manifest["notes"]
    assert "permanently out of scope" in notes["enforcement_mode"].lower()
    assert "not_proven" in notes["host_verification_status"].lower()
    assert any("Go Nose" in stage for stage in manifest["golden_path"])
    assert not any("direct Npcap" in stage for stage in manifest["golden_path"])
    assert not any("wfp (windows enforcement)" in stage.lower() for stage in manifest["golden_path"])

    for module in (
        "src/capture/npcap_capture.zig",
        "src/capture/proto/l7_payload.zig",
        "src/detection/proto_anomaly.zig",
        "src/xdr/xdr_incident_fabric.zig",
    ):
        assert manifest["modules"][module]["status"] == "LAB"
        assert manifest["modules"][module]["golden_path"] is False

    wfp = manifest["modules"]["src/policy/wfp_production.zig"]
    assert wfp["status"] == "REAL"
    assert wfp["golden_path"] is False
    assert "fail-closed" in wfp["role"].lower()


def test_go_transport_boundary_is_not_mislabeled_as_c_abi() -> None:
    system = _json("SYSTEM_MAP.json")
    components = {item["id"]: item for item in system["components"]}
    assert "length-prefixed windows named pipe" in components["go_nose"]["boundary"].lower()
    aggregator = components["aggregator"]["boundary"]
    assert "REST sidecar" in aggregator
    assert "c abi -> zig" not in aggregator.lower()

    contract = _json("CONTRACT_MAP.json")
    canonical = next(item for item in contract["contracts"] if item["id"] == "CONTRACT-01")
    assert "Python Brain" in canonical["producer"]
    assert "not this wire schema" in canonical["producer"]
    assert "EventQueue" in canonical["consumer"]


def test_data_flow_is_production_detection_only_and_all_file_paths_exist() -> None:
    flow_map = _json("FLOW_MAP.json")
    data = next(flow for flow in flow_map["flows"] if flow["id"] == "DATA-001")
    assert data["status"] == "PRODUCTION_DETECTION_ONLY"
    assert "IDS Evidence Receipt" in data["name"]
    assert "enforcement" not in data["name"].lower()
    assert any("host effects" in layer.get("note", "").lower() for layer in data["layers"])

    for flow in flow_map["flows"]:
        for layer in flow["layers"]:
            for field in ("file", "consumer_file", "receipt_contract", "bridge_file"):
                path = layer.get(field)
                if path is not None:
                    assert _source_exists(path), f"{flow['id']} step {layer['step']} has invalid {field}: {path!r}"


def test_brain_reference_flow_is_not_confused_with_optional_python_runtime_flow() -> None:
    flow_map = _json("FLOW_MAP.json")
    reference = next(flow for flow in flow_map["flows"] if flow["id"] == "BRAIN-001")
    runtime = next(flow for flow in flow_map["flows"] if flow["id"] == "BRAIN-002")

    assert reference["status"] == "LAB_TEST_ONLY_NOT_RUNTIME_WIRED"
    assert "quarantined from the daemon" in reference["description"]
    assert runtime["status"] == "OPTIONAL_ADVISORY_NOT_A_DIRECT_POLICY_DECISION"
    assert "not a direct ThreatScore-to-policy command" in runtime["description"]
    returned = next(layer for layer in runtime["layers"] if layer["step"] == 4)
    assert "source=detection_brain" in returned["output"]


def test_authority_and_system_maps_keep_pep_and_xdr_boundaries() -> None:
    authority = _json("AUTHORITY_MAP.json")
    invariants = "\n".join(authority["invariants"]).lower()
    assert "production host-effect activation is out of scope" in invariants
    assert "rust pep" in invariants
    assert "contradictory source-of-truth documents" in [item.lower() for item in authority["stop_the_line"]]

    system = _json("SYSTEM_MAP.json")
    modules = system["components"][0]["modules"]
    engine = next(module for module in modules if module["name"] == "xdr/xdr_engine")
    fabric = next(module for module in modules if module["name"] == "xdr/xdr_incident_fabric")
    assert "not production-wired" in engine["role"].lower()
    assert "selected" in fabric["role"].lower() and "advisory" in fabric["role"].lower()


def test_production_gate_and_ids_receipt_order_match_the_maps() -> None:
    build = (REPO / "build.zig").read_text(encoding="utf-8")
    daemon = (REPO / "src/daemon.zig").read_text(encoding="utf-8")
    pep = (REPO / "src/policy/pep_bindings.zig").read_text(encoding="utf-8")
    wfp = (REPO / "src/policy/wfp_production.zig").read_text(encoding="utf-8")
    processor = (REPO / "src/pipeline/event_processor.zig").read_text(encoding="utf-8")

    assert "lab-prevention-gate" in build and "orelse false" in build
    assert "if (build_options.lab_prevention_gate)" in daemon
    assert "if (policy.isHostMutating(action) and !gate_open) return .escalate;" in pep
    assert "return .unavailable;" in wfp

    append_at = processor.index("const forensic_seq = appendForensicRecord(")
    hash_at = processor.index("forensic_ring.recordHash(forensic_seq)")
    issue_at = processor.index("ids_receipt.issue(")
    assert append_at < hash_at < issue_at
