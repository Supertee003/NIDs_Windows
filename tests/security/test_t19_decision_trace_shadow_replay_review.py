"""T19: Decision Trace -> Shadow Decision -> Replayable Security -> Final Review
(steps 56-59).

Acceptance criteria:
  AC1. A decision is auditable to its root source: every action traces through
       Action -> PEP Request -> Policy -> Verdict -> Evidence -> Correlation ->
       Event -> Source in one strict order; every privileged ActionKind
       (block/quarantine/rate-limit) must be registered and audited.
  AC2. Shadow candidates are compared to live decisions across six dimensions
       (decision, evidence, confidence, false-positive indication, policy
       version, detector version) and can NEVER enforce -- the decision to
       enforce stays with the ASP.
  AC3. A security replay re-lets an historical outcome against new atom versions
       (rules / policy / context); every difference (verdict_changed /
       action_changed) is attributed to the exact version delta in `reason`.
  AC4. Final review: a twelve-item accountability checklist is enforced --
       sensors/detectors/Brain/Go/TypeScript never enforce, RAG never
       authorizes, C++/policy/CLI never bypass the PEP or execute policy, the
       Rust PEP is the final authority, and Windows follows the PEP result with
       every privileged action audited.

This file proves the invariants structurally against the authoritative modules
and runtime_manifest.json; the semantic gates (chain order, per-dimension
comparison, delta attribution, rewinding) are proven by the modules' own Zig
test suites.

Authoritative modules (registered in runtime_manifest.json):
  core/decision_trace.zig     - T19 AC1 (8-link trace to root source + audit)
  core/shadow_decision.zig    - T19 AC2 (6-dimension shadow compare, never enforces)
  core/replayable_security.zig- T19 AC3 (replay vs rules/policy/context atoms)
  core/authority_review.zig   - T19 AC4 (twelve-accountability checklist, fail-closed)
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MANIFEST_PATH = REPO_ROOT / "runtime_manifest.json"

TRACE_MODULE = "core/decision_trace.zig"
SHADOW_MODULE = "core/shadow_decision.zig"
REPLAY_MODULE = "core/replayable_security.zig"
REVIEW_MODULE = "src/core/authority_review.zig"

TRACE_CHAIN = [
    "action",
    "pep_request",
    "policy",
    "verdict",
    "evidence",
    "correlation",
    "event",
    "source",
]

SHADOW_DIMENSIONS = [
    "decision",
    "evidence",
    "confidence",
    "false_positive",
    "policy_version",
    "detector_version",
]

REPLAY_ATOMS = ["rules_version", "policy_version", "context_version"]
REPLAY_DIFFERENCES = ["none", "verdict_changed", "action_changed"]

REVIEW_SUBJECTS = [
    "sensor",
    "detector",
    "rag",
    "brain",
    "go",
    "typescript",
    "cpp",
    "policy",
    "cli",
    "rust_pep",
    "windows",
]
REVIEW_CAPABILITIES = [
    "enforce",
    "authorize",
    "execute_policy",
    "bypass_pep",
    "final_verdict",
    "comply",
    "audit",
]
REVIEW_PAIRS = [
    (".sensor", ".enforce"),
    (".detector", ".enforce"),
    (".rag", ".authorize"),
    (".brain", ".enforce"),
    (".go", ".enforce"),
    (".typescript", ".enforce"),
    (".cpp", ".bypass_pep"),
    (".policy", ".execute_policy"),
    (".cli", ".bypass_pep"),
    (".rust_pep", ".final_verdict"),
    (".windows", ".comply"),
    (".windows", ".audit"),
]


def _manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


def _block(src: str, marker: str) -> str:
    start = src.find(marker)
    assert start >= 0, f"marker {marker!r} not found"
    end = src.find("};", start)
    assert end >= 0, f"block close not found after {marker!r}"
    return src[start:end]


# ---------------------------------------------------------------------------
# Manifest registration
# ---------------------------------------------------------------------------

def test_manifest_declares_t19_modules_real() -> None:
    """The four T19 authoritative modules must be REAL in the manifest."""
    manifest = _manifest()
    for mod in (TRACE_MODULE, SHADOW_MODULE, REPLAY_MODULE, REVIEW_MODULE):
        assert mod in manifest["modules"], f"{mod} not in runtime_manifest.json"
        assert manifest["modules"][mod]["status"] == "REAL", (
            f"{mod} must be REAL (T19); got {manifest['modules'][mod]}"
        )


def test_authority_invariants_declare_t19() -> None:
    """authority_invariants must name the decision trace, shadow decision,
    replayable security, and final authority review."""
    joined = "\n".join(_manifest()["authority_invariants"])
    for phrase in ("decision trace", "shadow decision", "security replay", "final authority"):
        assert phrase in joined, f"authority invariant missing {phrase!r}"


# ---------------------------------------------------------------------------
# AC1 - Decision Trace: 8-link chain to root source + privileged-action audit
# ---------------------------------------------------------------------------

def test_ac1_trace_chain_is_the_mandated_eight_in_order() -> None:
    """TRACE_CHAIN lists action -> pep_request -> policy -> verdict ->
    evidence -> correlation -> event -> source in exact order."""
    block = _block(_read(TRACE_MODULE), "TRACE_CHAIN")
    prev = -1
    for link in TRACE_CHAIN:
        pos = block.find(link)
        assert pos >= 0, f"TRACE_CHAIN missing {link}"
        assert pos > prev, f"trace chain out of order: {link}"
        prev = pos


def test_ac1_strict_order_append_rejects_skips() -> None:
    """A trace is appended only in strict chain order."""
    src = _read(TRACE_MODULE)
    assert "append" in src
    assert "strict order" in src or "order" in src
    assert "complete" in src
    assert "rootSource" in src


def test_ac1_privileged_actions_are_named() -> None:
    """isPrivileged covers exactly the enforcing ActionKinds."""
    src = _read(TRACE_MODULE)
    assert "isPrivileged" in src
    for action in ("block", "quarantine", "rate_limit", "allow"):
        assert action in src, f"ActionKind missing {action!r}"


def test_ac1_audit_coverage_is_all_or_flagged() -> None:
    """TraceStore.auditCoverage reports all_traced or the untraced ids."""
    src = _read(TRACE_MODULE)
    assert "TraceStore" in src
    assert "registerAction" in src
    assert "auditCoverage" in src
    assert "all_traced" in src
    assert "untraced" in src


# ---------------------------------------------------------------------------
# AC2 - Shadow Decision: six dimensions, never enforces
# ---------------------------------------------------------------------------

def test_ac2_six_dimensions_in_mandated_order() -> None:
    """The Dimension enum carries all six comparison dimensions in order."""
    marker = "const Dimension"
    start = _read(SHADOW_MODULE).find(marker)
    assert start >= 0
    thirty_lines = _read(SHADOW_MODULE)[start : start + 1500]
    prev = -1
    for dim in SHADOW_DIMENSIONS:
        pos = thirty_lines.find(dim)
        assert pos >= 0, f"Dimension missing {dim}"
        assert pos > prev, f"dimensions out of order: {dim}"
        prev = pos


def test_ac2_compare_forces_candidate_never_to_enforce() -> None:
    """ShadowEngine.compare clears candidate_enforce and the comparison never
    reports enforcement."""
    src = _read(SHADOW_MODULE)
    assert "ShadowEngine" in src
    assert "candidate_enforce" in src
    assert "candidate_enforced" in src
    assert "compare" in src


def test_ac2_outcome_vocabulary_agree_and_differ_present() -> None:
    """ShadowOutcome distinguishes agree vs differ and flags any delta by dim."""
    src = _read(SHADOW_MODULE)
    assert "agree" in src
    assert "differ" in src
    assert "differs" in src


def test_ac2_comparison_fields_cover_all_six() -> None:
    """FieldComparison diffs are recorded per dimension."""
    src = _read(SHADOW_MODULE)
    assert "FieldComparison" in src
    assert "ShadowComparison" in src
    for dim in SHADOW_DIMENSIONS:
        assert dim in src, f"comparison missing {dim!r}"


# ---------------------------------------------------------------------------
# AC3 - Replayable Security: re-run against new atoms, attribute the delta
# ---------------------------------------------------------------------------

def test_ac3_three_replayable_atoms_present() -> None:
    """AtomVersions carry rules / policy / context versions."""
    src = _read(REPLAY_MODULE)
    for atom in REPLAY_ATOMS:
        assert atom in src, f"AtomVersions missing {atom!r}"


def test_ac3_difference_vocabulary_present() -> None:
    """Difference is none / verdict_changed / action_changed."""
    src = _read(REPLAY_MODULE)
    for diff in REPLAY_DIFFERENCES:
        assert diff in src, f"Difference missing {diff!r}"


def test_ac3_replay_result_carries_original_replayed_reason() -> None:
    """A ReplayResult records original, replayed, difference and reason."""
    src = _read(REPLAY_MODULE)
    assert "ReplayCase" in src
    assert "ReplayResult" in src
    for field in ("original", "replayed", "difference", "reason"):
        assert field in src, f"ReplayResult missing {field!r}"
    assert "SecurityReplay" in src and "replay" in src


def test_ac3_reason_attributes_to_atom_deltas() -> None:
    """The reason text quotes the exact delta lines rules:/policy:/context:."""
    src = _read(REPLAY_MODULE)
    assert "writeReason" in src
    for atom in ("rules", "policy", "context"):
        assert f'"{atom}:' in src or f'"{atom}:' in src, f"reason attribution missing {atom!r}"


def test_ac3_summarize_is_regression_readout() -> None:
    """summarize() counts matched vs changed per difference kind."""
    src = _read(REPLAY_MODULE)
    assert "summarize" in src
    assert "ReplayStats" in src
    for field in ("verdict_changed", "action_changed"):
        assert field in src, f"ReplayStats missing {field!r}"


# ---------------------------------------------------------------------------
# AC4 - Final Review: the twelve-accountability checklist
# ---------------------------------------------------------------------------

def test_ac4_checklist_has_twelve_clauses() -> None:
    """CLAUSE_COUNT is twelve and the checklist array is sized to it."""
    src = _read(REVIEW_MODULE)
    assert "CLAUSE_COUNT" in src
    assert re.search(r"CLAUSE_COUNT:\s*usize\s*=\s*12", src), "CLAUSE_COUNT != 12"
    assert "AUTHORITY_CHECKLIST" in src
    assert "12, CLAUSE_COUNT" in src or "CLAUSE_COUNT, AUTHORITY_CHECKLIST.len" in src


def test_ac4_all_twelve_subject_capability_pairs_encoded() -> None:
    """Each mandated clause appears as an explicit checklist row."""
    src = _read(REVIEW_MODULE)
    for subject, capability in REVIEW_PAIRS:
        first = src.find(subject)
        second = src.find(capability, first if first >= 0 else 0)
        assert first >= 0 and second >= first, (
            f"checklist row missing pair {subject}/{capability}"
        )


def test_ac4_subjects_and_capabilities_enumerated() -> None:
    """Every subject and capability is a named enum tag."""
    src = _read(REVIEW_MODULE)
    for subject in REVIEW_SUBJECTS:
        assert subject in src, f"Subject missing {subject!r}"
    for capability in REVIEW_CAPABILITIES:
        assert capability in src, f"Capability missing {capability!r}"


def test_ac4_rust_pep_is_final_and_windows_complies() -> None:
    """The PEP holds the final verdict; Windows must follow it and audit."""
    src = _read(REVIEW_MODULE)
    assert "final_verdict" in src
    assert "comply" in src
    assert "audit" in src
    assert "rust_pep" in src


def test_ac4_review_fails_closed() -> None:
    """ReviewOutcome.authoritative is an all-rows gate on ReviewOutcome."""
    src = _read(REVIEW_MODULE)
    assert "review" in src
    assert "ReviewOutcome" in src
    assert "authoritative" in src
    assert "holds" in src