"""T18 legacy lab IPS tests plus the ADR-0009 XDR evidence contract.

Acceptance criteria:
  AC1. Lab-only IPS code progresses through the canary order -- Detection Only -> Shadow ->
       Canary -> Limited Enforcement -> Expanded Enforcement -- with the canary
       specifying scope, target, expiry, rollback, and audit.
  AC2. Lab-only IPS helpers exercise the Rust PEP + WFP contract across allow / block /
       quarantine / rate-limit / expiry / revoke / rollback / driver-unavailable
       (driver-unavailable is fail-closed); this does not enable production IPS.
  AC3. XDR combines evidence from multiple source categories
       (Network / Host / Process / File / Registry / Identity / Threat Intel /
       Historical / Federation) into an advisory incident assessment only; it
       has no policy action and cannot claim PEP dispatch.

This file proves structural invariants against lab/test modules and
runtime_manifest.json; it is not production host-effect evidence. Semantic
incident aggregation is exercised by the module's Zig test suite.

Registered lab/test modules in runtime_manifest.json:
  src/windows/ips_canary_order.zig - T18 AC1 (lab-only canary order)
  src/core/real_ips_path.zig       - T18 AC2 (lab-only IPS contract)   src/xdr/xdr_incident_fabric.zig  - ADR-0009 selected XDR authority (advisory-only; runtime-wired read-only via XDR-WIRE-001)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MANIFEST_PATH = REPO_ROOT / "runtime_manifest.json"

CANARY_MODULE = "src/windows/ips_canary_order.zig"
REAL_IPS_MODULE = "src/core/real_ips_path.zig"
XDR_MODULE = "src/xdr/xdr_incident_fabric.zig"

CANARY_ORDER = [
    "detection_only",
    "shadow",
    "canary",
    "limited_enforcement",
    "expanded_enforcement",
]

REAL_IPS_CHAIN = [
    "telemetry",
    "detection",
    "verdict",
    "policy",
    "signature_verification",
    "rust_pep",
    "wfp",
]

XDR_SOURCE_CATEGORIES = [
    "network",
    "host",
    "process",
    "file",
    "registry",
    "identity",
    "threat_intel",
    "historical",
    "federation",
]

ENFORCEMENT_MATRIX = [
    "allow",
    "block",
    "quarantine",
    "rate_limit",
    "expiry",
    "revoke",
    "rollback",
    "driver-unavailable",
]


def _manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Manifest registration
# ---------------------------------------------------------------------------

def test_manifest_declares_t18_modules_non_production() -> None:
    """Legacy IPS and the selected XDR fabric must not be golden-path production modules."""
    manifest = _manifest()
    for mod in (CANARY_MODULE, REAL_IPS_MODULE, XDR_MODULE):
        assert mod in manifest["modules"], f"{mod} not in runtime_manifest.json"
        assert manifest["modules"][mod]["status"] == "LAB", (
            f"{mod} must be LAB-only; got {manifest['modules'][mod]}"
        )
        assert manifest["modules"][mod]["golden_path"] is False
    assert "advisory-only" in manifest["modules"][XDR_MODULE]["role"]
    assert "read-only" in manifest["modules"][XDR_MODULE]["role"]


def test_authority_invariants_declare_lab_ips_and_evidence_only_xdr() -> None:
    """Authority claims must keep IPS lab-only and XDR evidence-only."""
    joined = "\n".join(_manifest()["authority_invariants"])
    assert "canary order" in joined
    assert "lab-only" in joined.lower()
    assert "multi-source" in joined
    assert "evidence-only" in joined
    assert "dispatched_to_pep" not in joined


def test_manifest_does_not_claim_unwired_xdr_runtime_order() -> None:
    """The advisory XDR fabric is module-wired (XDR-WIRE-001) but is still not a
    named runtime init/shutdown stage until source-to-forensic wiring is proven."""
    manifest = _manifest()
    for order in ("init_order", "shutdown_order"):
        assert not any("xdr" in module.lower() for module in manifest[order])


# ---------------------------------------------------------------------------
# AC1 - IPS Canary order (scope / target / expiry / rollback / audit)
# ---------------------------------------------------------------------------

def test_ac1_canary_order_is_mandated_sequence() -> None:
    """The promotion order constant must be the mandated five stages in
    exact order."""
    src = _read(CANARY_MODULE)
    idx = min(src.find(s) for s in CANARY_ORDER)
    assert idx >= 0
    # Extract the PROMOTION_ORDER block and confirm real ordering.
    marker = "PROMOTION_ORDER"
    start = src.find(marker)
    end = src.find("};", start)
    block = src[start:end]
    prev = -1
    for stage in CANARY_ORDER:
        pos = block.find(stage)
        assert pos >= 0, f"PROMOTION_ORDER missing {stage}"
        assert pos > prev, f"stages out of order: {stage}"
        prev = pos


def test_ac1_canary_stage_vocabulary_has_rolled_back() -> None:
    """A fail-closed rolled_back stage exists that never applies."""
    src = _read(CANARY_MODULE)
    assert "rolled_back" in src
    assert "stageApplies" in src


def test_ac1_canary_spec_carries_scope_target_expiry() -> None:
    """The canary spec carries scope (CIDR), target (port) and expiry."""
    src = _read(CANARY_MODULE)
    assert "scope_cidr_base" in src
    assert "scope_prefix_len" in src
    assert "target_port" in src
    assert "expiry_after_ms" in src


def test_ac1_canary_rollback_and_audit_present() -> None:
    """Rollback (auto + manual) and a bounded audit trail are present."""
    src = _read(CANARY_MODULE)
    assert "manualRollback" in src
    assert "auto_rollback_consecutive" in src
    assert "auto_rollback_fail_rate" in src
    assert "AuditEntry" in src and "audit_len" in src


def test_ac1_canary_scope_is_canary_only() -> None:
    """The canary stage must be pinned to the canary test-net, never real
    traffic; expansion to real traffic only at expanded_enforcement."""
    src = _read(CANARY_MODULE)
    assert "CANARY_IP_BASE" in src
    assert "CANARY_MAGIC" in src
    assert "limited_enforcement" in src
    assert "expanded_enforcement" in src


def test_ac1_gates_are_fail_closed() -> None:
    """Promotion requires all gates (observations, fail rate, dwell) to
    hold and human approval for the limited -> expanded transition."""
    src = _read(CANARY_MODULE)
    assert "min_observations" in src
    assert "max_fail_bps" in src
    assert "min_dwell_ms" in src
    assert "human_approval_missing" in src


# ---------------------------------------------------------------------------
# AC2 - Real IPS path through Rust PEP + WFP (full enforcement matrix)
# ---------------------------------------------------------------------------

def test_ac2_real_ips_chain_is_ordered() -> None:
    """The chain constant must list every link in mandated order."""
    src = _read(REAL_IPS_MODULE)
    marker = "CHAIN_ORDER"
    start = src.find(marker)
    end = src.find("};", start)
    block = src[start:end]
    prev = -1
    for link in REAL_IPS_CHAIN:
        pos = block.find(link)
        assert pos >= 0, f"CHAIN_ORDER missing {link}"
        assert pos > prev, f"chain out of order: {link}"
        prev = pos


def test_ac2_enforcement_matrix_is_tested() -> None:
    """Every mandated dimension of the enforcement matrix is present."""
    src = _read(REAL_IPS_MODULE)
    for dim in ENFORCEMENT_MATRIX:
        assert dim in src, f"enforcement matrix missing {dim!r}"


def test_ac2_driver_unavailable_is_fail_closed() -> None:
    """driver-unavailable must never silently allow a block."""
    src = _read(REAL_IPS_MODULE)
    assert "unavailable" in src
    assert "fail_closed" in src
    assert "isBlocked" in src


def test_ac2_reaches_rust_pep_then_wfp() -> None:
    """The chain reaches the Rust PEP and WFP links in order."""
    src = _read(REAL_IPS_MODULE)
    assert "rust_pep" in src and "wfp" in src
    assert "signature_verification" in src


def test_ac2_real_block_is_rule_based() -> None:
    """Real blocks become durable rules with lifecycle ops."""
    src = _read(REAL_IPS_MODULE)
    assert "Rule" in src and "active" in src
    assert "expire" in src and "revoke" in src
    assert "rollback" in src


# ---------------------------------------------------------------------------
# AC3 - XDR multi-source evidence correlation (advisory assessment only)
# ---------------------------------------------------------------------------

def test_ac3_all_nine_source_categories_present() -> None:
    """The four legacy categories plus registry/identity/threat-intel/
    historical/federation are enumerated."""
    src = _read(XDR_MODULE)
    for cat in XDR_SOURCE_CATEGORIES:
        assert cat in src, f"source category missing {cat!r}"


def test_ac3_pipeline_stages_present() -> None:
    """Entity -> Evidence -> Incident -> advisory assessment has no action stage."""
    src = _read(XDR_MODULE)
    for term in ("Evidence", "Incident", "Decision", "Assessment", "entity"):
        assert term in src, f"pipeline stage missing {term!r}"
    assert "Action" not in src


def test_ac3_single_incident_holds_multiple_sources_without_pep_dispatch_claim() -> None:
    """Multi-source correlation is advisory evidence and cannot claim PEP dispatch."""
    src = _read(XDR_MODULE)
    assert "distinctSources" in src
    assert "source_bitmask" in src or "sources" in src
    assert "dispatched_to_pep" not in src
    assert "isEnforcement" not in src


def test_ac3_decision_reports_evidence_severity_without_action_authority() -> None:
    """The public assessment preserves severity and correlation only."""
    src = _read(XDR_MODULE)
    assert "pub fn decide(" in src
    assert "pub const Decision = struct" in src
    assert "source_categories_used" in src
    assert "DecisionAction" not in src
    assert "dispatched_to_pep" not in src
    for forbidden in ("rate_limit", "quarantine", "DecisionAction.block"):
        assert forbidden not in src, f"XDR must not expose enforcement action {forbidden!r}"
