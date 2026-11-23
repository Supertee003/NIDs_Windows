"""P4-RUNTIME-TRUTH pins: current-facing authority and source-of-truth labels.

Records-only E1 guards. They stop the retired enforcement-authority vocabulary
and the pre-P4 build-source / core/ contradictions from returning to the
current-facing tree. Frozen release snapshots under release/ are deliberately
not touched or asserted here.
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONTROL = REPO / "tools" / "aegisctl" / "api" / "control_api.py"
CLI = REPO / "tools" / "aegisctl.py"


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def test_no_enforcement_authority_label_survives_in_current_tooling() -> None:
    for path in (CONTROL, CLI):
        text = path.read_text(encoding="utf-8")
        assert "sole_enforcement_authority" not in text, (
            f"{path.name} still claims a sole enforcement authority"
        )
        assert "canonical_enforcement_authority" not in text, (
            f"{path.name} still publishes a canonical_enforcement_authority key"
        )


def test_diagnostic_payload_names_detection_only_authority() -> None:
    from tools.aegisctl.api import control_api

    payload = control_api._diagnostic_health_payload("p4-label-test")
    assert payload["canonical_detection_policy_authority"] == "rust_pep"
    assert payload["authority_model"] == "DETECTION_ONLY_NO_HOST_EFFECT"
    assert "canonical_enforcement_authority" not in payload
    assert payload["rust_pep"]["authority"] == "detection_only_policy_authority"
    assert payload["rust_pep"]["authority_model"] == "DETECTION_ONLY_NO_HOST_EFFECT"
    assert payload["rust_pep"]["host_effect_capable"] is False
    assert payload["rust_shield"]["alias_of"] == "rust_pep"
    assert payload["rust_shield"]["canonical"] is False


def test_agents_build_source_matches_the_current_maps() -> None:
    system = json.loads(_read("SYSTEM_MAP.json"))
    flow = json.loads(_read("FLOW_MAP.json"))
    build_truth = json.loads(_read("build_truth.json"))
    sha = system["head_sha"]
    assert flow["head_sha"] == sha
    assert build_truth["head_sha"] == sha
    assert f"**BUILD SOURCE HEAD:** `{sha}`" in _read("AGENTS.md")
    assert "records-only commits do not move it" in json.dumps(build_truth["notes"])


def test_nose_boundary_has_no_unimplemented_tcp_fallback_claim() -> None:
    flow_text = _read("FLOW_MAP.json")
    assert "development fallback" not in flow_text
    assert "no TCP fallback is implemented" in flow_text


def test_core_directory_is_not_claimed_as_a_tracked_tree() -> None:
    manifest = json.loads(_read("runtime_manifest.json"))
    note = manifest["notes"]["legacy_folder"]
    assert "NO tracked or filesystem tree" in note
    assert "module-ID aliases" in note
    assert "tracked per user request" not in note
    assert "core/ has NO tracked or filesystem tree" in _read("tools/create_manifest.py")


def test_legacy_summary_script_carries_no_live_enforcement_claim() -> None:
    text = _read("scripts/summary_detection_path.py")
    for stale in (
        "WFP enforcement (GAP-005 closed)",
        "WFP Enforcement (Rust PEP -> Windows)",
        "38 entries (E0-E7), all carry current HEAD",
        "sole_enforcement_authority",
    ):
        assert stale not in text, f"legacy summary still claims: {stale!r}"
    assert "HISTORICAL" in text
