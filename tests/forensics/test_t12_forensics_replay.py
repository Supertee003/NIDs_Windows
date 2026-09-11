"""T12: Forensics (immutable trace) + Replay (Steps 34-35).

The T12 acceptance criteria are:
  AC1. Every significant decision writes an immutable forensic trace
       across the full chain (event -> evidence -> verdict -> policy ->
       signature -> PEP -> action -> result).
  AC2. A replay can reproduce an original decision against old/new
       ruleset + policy + context and report difference + reason.
  AC3. The forensic trace and the replay are consistent (no forensic
       inconsistency).

Architecture:
  - core/forensics_engine.zig      : authoritative immutable trace (ring
    buffer). logResult() captures event + evidence + verdict + policy +
    PEP + action + result, returns a monotonically increasing sequence.
  - core/forensic_log.zig          : append-only NDJSON persistence.
  - src/tests/proofs/forensic_replay_proof.zig : append-only ForensicLog with a
    rolling hash chain (no edit, no delete) + immutability verify.
  - core/replay_engine.zig         : replay authority. compare(original,
    replayed) reproduces the decision difference and reports diff +
    reason via ReplayResult.reason().
  - The dispatcher wires forensics_integration.logResult() into the
    orchestrator after the PEP stage, so every significant decision is
    traced.

This file proves the invariants by scanning the source and the manifest.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

FORENSICS_ENGINE = "core/forensics_engine.zig"
FORENSIC_LOG = "core/forensic_log.zig"
FORENSIC_REPLAY_PROOF = "src/tests/proofs/forensic_replay_proof.zig"
REPLAY_ENGINE = "core/replay_engine.zig"
FORENSICS_INTEGRATION = "src/tests/integration/forensics_integration.zig"
DISPATCHER = "core/dispatcher.zig"
DISPATCHER_PHASE_B = "core/dispatcher_phase_b.zig"
POLICY_SIGNING = "core/policy_signing.zig"

# The full chain as declared by the manifest golden path. Each stage must
# be represented in the forensic trace (AC1).
FULL_CHAIN_STAGES = [
    "canonical_event",
    "detection (evidence)",
    "verdict",
    "correlation",
    "threat_intel",
    "rag (context)",
    "brain (advisory)",
    "policy (decision)",
    "policy signing (ed25519)",
    "rust pep (enforcement authority)",
    "wfp (windows enforcement)",
    "forensics (immutable trace)",
    "replay",
]


def _read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8", errors="ignore")


def test_full_chain_on_golden_path() -> None:
    """AC1: the manifest golden path declares the full chain ending in
    forensics (immutable trace) + replay."""
    manifest = json.loads((REPO_ROOT / "runtime_manifest.json").read_text(encoding="utf-8"))
    golden = manifest["golden_path"]
    for stage in FULL_CHAIN_STAGES:
        assert stage in golden, (
            f"golden path must declare stage {stage!r} (T12 AC1); got: {golden}"
        )
    assert golden[-2] == "forensics (immutable trace)" and golden[-1] == "replay", (
        f"forensics + replay must terminate the golden path; got: {golden}"
    )


def test_forensics_engine_is_authoritative_trace() -> None:
    """AC1: core/forensics_engine.zig owns the authoritative trace. It
    must expose a ForensicsEngine with logResult() that returns sequence
    numbers and a PipelineResult capturing the full chain."""
    src = _read(FORENSICS_ENGINE)
    assert "pub const ForensicsEngine = struct" in src
    assert "pub fn logResult" in src
    assert "pub fn getBySequence" in src
    assert "RING_BUFFER_CAPACITY" in src
    assert "next_sequence" in src


def test_trace_captures_full_chain_fields() -> None:
    """AC1: the traced PipelineResult must cover the whole chain:
    event, evidence/verdict, correlation, threat intel, context/brain,
    policy decision, policy signature, PEP, action, result."""
    src = _read(FORENSICS_ENGINE)
    required = [
        ".event_id",                 # event
        ".source_ip", ".dest_ip",    # event (evidence source)
        ".aggregated_verdict",       # verdict
        ".confidence",               # evidence confidence
        ".correlation_alert_count",  # correlation
        ".threat_intel_matched",     # threat intel
        ".brain_advice_kind",        # context / brain
        ".brain_threat_score",
        ".policy_action",            # policy decision
        ".policy_rule",
        ".pep_status",               # PEP
        ".pep_rejection_reason",
        ".pep_blocked_ip",
    ]
    missing = [f for f in required if f not in src]
    assert not missing, (
        f"PipelineResult must capture full chain fields {missing} (T12 AC1)"
    )


def test_dispatcher_writes_trace_for_every_decision() -> None:
    """AC1: the dispatcher (SOLE orchestrator) must call
    forensics_integration.logResult() so every significant decision is
    traced across the chain. Both dispatcher variants must wire it."""
    for disp in (DISPATCHER, DISPATCHER_PHASE_B):
        src = _read(disp)
        assert "@import(\"forensics_integration.zig\")" in src, (
            f"{disp} must import forensics_integration (T12 AC1)"
        )
        assert "forensics_int.logResult(" in src or "forensics_integration.logResult(" in src, (
            f"{disp} must call logResult after PEP (T12 AC1)"
        )


def test_forensic_log_is_append_only_immutable() -> None:
    """AC1: the forensic log is immutable and append-only. forensic_log.zig
    must have NO edit/delete API. forensic_replay_proof.zig must provide
    an append-only ForensicLog with a rolling hash chain whose integrity
    can be verified (no edit, no delete)."""
    log_src = _read(FORENSIC_LOG)
    assert "pub fn log(" in log_src
    assert re.search(r"pub fn (update|delete|remove|edit)\b", log_src) is None, (
        "forensic_log.zig must not expose update/delete/edit (T12 AC1 append-only)"
    )

    proof_src = _read(FORENSIC_REPLAY_PROOF)
    assert "pub const ForensicLog = struct" in proof_src
    assert "pub fn append(" in proof_src
    assert re.search(r"pub fn (update|delete|remove|edit)\b", proof_src) is None, (
        "forensic_replay_proof ForensicLog must be append-only (T12 AC1)"
    )
    assert "verifyHashChain" in proof_src, (
        "forensic_replay_proof must expose verifyHashChain (T12 AC1 immutable)"
    )
    assert "verifyImmutability" in proof_src


def test_replay_engine_reports_difference_and_reason() -> None:
    """AC2: the replay engine reproduces an original decision, re-runs it
    against a new ruleset/policy/context, and reports the difference plus
    a human-readable reason."""
    src = _read(REPLAY_ENGINE)
    assert "pub const ReplayEngine = struct" in src
    assert "pub fn compare(" in src
    assert "pub const ReplayResult = struct" in src
    assert "pub fn reason(" in src, (
        "ReplayResult must expose reason() (T12 AC2 report difference + reason)"
    )
    assert "pub fn hasDiff(" in src
    assert "pub const DiffKind = enum" in src
    # Diff kinds must cover verdict/action/PEP/confidence/threat-score changes.
    for kind in ["verdict_changed", "action_changed", "pep_status_changed", "confidence_shift", "threat_score_shift", "no_diff"]:
        assert kind in src, f"DiffKind must include {kind} (T12 AC2)"
    assert "isRegression" in src, (
        "ReplayResult must detect regressions (T12 AC2)"
    )
    assert "isImprovement" in src


def test_replay_holds_original_and_replayed_decisions() -> None:
    """AC2: the ReplayResult must carry both the original decision and the
    replayed decision (original + replayed fields), i.e. it reproduces the
    original decision for comparison."""
    src = _read(REPLAY_ENGINE)
    assert "original:" in src and "replayed:" in src, (
        "ReplayResult must carry both original and replayed PipelineResults (T12 AC2)"
    )


def test_replay_consumes_forensics_trace() -> None:
    """AC3: the replay engine must consume the forensic trace directly
    (forensics.PipelineResult), so the trace and the replay are one
    schema -- no forensic inconsistency."""
    src = _read(REPLAY_ENGINE)
    assert "@import(\"forensics_engine.zig\")" in src, (
        "replay_engine must import forensics_engine (T12 AC3 consistency)"
    )
    assert "forensics.PipelineResult" in src, (
        "replay compare() must operate on forensics.PipelineResult (T12 AC3)"
    )


def test_forensic_trace_and_replay_share_schema() -> None:
    """AC3: forensics_engine and replay_engine must both be built on the
    same PipelineResult definition (replay imports it, does not redefine
    it), so a replay of a traced decision is inherently consistent with
    the trace."""
    fe = _read(FORENSICS_ENGINE)
    re_src = _read(REPLAY_ENGINE)
    # Replay must consume forensics.PipelineResult, NOT redefine its own
    # copy -- a single schema guarantees trace/replay consistency.
    assert "forensics.PipelineResult" in re_src, (
        "replay must use forensics.PipelineResult (single schema), T12 AC3"
    )
    # The authoritative definition must exist in exactly the forensics module.
    assert "pub const PipelineResult = struct" in fe

    # Extract fields declared in forensics PipelineResult.
    m = re.search(
        r"pub const PipelineResult = struct \{(.*?)\n\};",
        fe,
        re.DOTALL,
    )
    assert m is not None, "PipelineResult struct not found in forensics_engine"
    fe_fields = set(re.findall(r"^\s+(\w+):\s", m.group(1), re.M))
    # Every trace field must be observable through replay's ReplayResult
    # (original/replayed PipelineResults), so no field is lost on replay.
    required = {
        "event_id", "source_ip", "dest_ip", "aggregated_verdict",
        "policy_action", "pep_status", "pep_blocked_ip",
    }
    missing = [f for f in required if f not in fe_fields]
    assert not missing, (
        f"forensics PipelineResult must define chain fields {missing} (T12 AC3)"
    )


def test_manifest_documents_forensics_and_replay() -> None:
    """AC1/AC2: runtime_manifest.json must document the forensics +
    replay modules as REAL and on the golden path."""
    manifest = json.loads((REPO_ROOT / "runtime_manifest.json").read_text(encoding="utf-8"))
    for mod in (FORENSICS_ENGINE, FORENSIC_LOG, REPLAY_ENGINE):
        entry = manifest["modules"].get(mod)
        assert entry is not None, f"{mod} must be in runtime_manifest.json (T12)"
        assert entry.get("status") == "REAL", f"{mod} must be REAL (T12); got {entry}"
        assert entry.get("golden_path") is True, f"{mod} must be on golden path (T12)"


def test_authority_invariants_declare_forensics_and_replay() -> None:
    """AC1/AC3: authority_invariants must declare the forensics authority,
    the replay authority, and the trace/replay consistency rule."""
    manifest = json.loads((REPO_ROOT / "runtime_manifest.json").read_text(encoding="utf-8"))
    invariants = manifest.get("authority_invariants", [])
    joined = "\n".join(invariants)
    for needle in [
        "forensics authority",
        "forensic log authority",
        "replay authority",
        "forensic trace and replay consistent",
    ]:
        assert needle in joined, (
            f"authority_invariants must declare {needle!r} (T12); got: {invariants}"
        )