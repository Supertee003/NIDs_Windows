"""P6-DOC-TRUTH pins: current-facing documentation parity.

Records-only E1 guards. They stop stale enforcement-authority vocabulary,
superseded release identity, the TCP-fallback claim, the 23/23 host-evaluable
claim and job/application outreach content from returning to current docs.
Frozen snapshots under release/, docs/historical/ and EVIDENCE_INDEX historical
records are deliberately not rewritten and are not checked here.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def test_ai_context_has_no_live_enforcement_authority_claim() -> None:
    text = _read("AI_CONTEXT.md")
    for stale in (
        "Final enforcement authority:",
        "Never create a second enforcement authority.",
        "Privileged action authorization",
        "Current evidence establishes Windows E5 for the shipped",
        "Current source/build slice (2026-11-03",
    ):
        assert stale not in text, stale
    assert "Detection-only policy/evidence authority:" in text
    assert "no host-effect authority exists" in text
    assert "HISTORICAL @ 2026-11-03" in text
    assert "current build source is `7822f4c`" in text


def test_ai_context_labels_source_path_abi_snapshot_as_historical() -> None:
    text = _read("AI_CONTEXT.md")
    assert "Historical ABI vocabulary (P6-DOC-TRUTH)" in text
    assert "shared/abi/pep_abi.md" in text
    assert "issue #45" in text


def test_contributing_drops_sole_enforcement_authority() -> None:
    text = _read("CONTRIBUTING.md")
    assert "the sole enforcement authority" not in text
    assert "Enforcement or driver changes" not in text
    assert "reintroduce a host-effect authority" in text
    assert "Rust PEP is detection-only" in text


def test_ai_context_fragments_are_detection_only() -> None:
    checks = {
        "docs/ai-context/01-semantic-map.md": "DETECTION POLICY (historical ENFORCE)",
        "docs/ai-context/02-runtime-spine.md": "Rust PEP (DETECTION POLICY)",
        "docs/ai-context/03-language-ownership.md": "No language can create a host-effect authority",
        "docs/ai-context/05-data-lifecycle.md": "Detection-only PEP Evidence",
        "docs/ai-context/governance.md": "ESCALATE reason 8",
        "docs/ai-context/10-current-phase.md": "ONE DETECTION POLICY AUTHORITY / NO HOST EFFECT",
    }
    for path, marker in checks.items():
        assert marker in _read(path), path
    spine = _read("docs/ai-context/02-runtime-spine.md")
    assert "Rust PEP (ENFORCE)" not in spine
    phase = _read("docs/ai-context/10-current-phase.md")
    assert "current build source after AUDIT-CLOSE-20261123" not in phase
    assert "The current build source is `7822f4c`" in phase


def test_architecture_authority_docs_are_scoped() -> None:
    authority = _read("docs/architecture/authority-map.md")
    assert "HISTORICAL in part (P6-DOC-TRUTH)" in authority
    assert "Detection-only evaluation + evidence; no host effect" in authority
    assert "[Windows Enforcement]" not in authority
    multi = _read("docs/architecture/MULTI_PROCESS_ARCHITECTURE.md")
    assert "HISTORICAL (P6-DOC-TRUTH)" in multi
    assert "WFP → Block/Allow" not in multi
    spine = _read("docs/architecture/RUNTIME_SPINE.md")
    assert "ONE ENFORCEMENT AUTHORITY" not in spine
    assert "ONE DETECTION POLICY AUTHORITY / NO HOST EFFECT" in spine


def test_historical_handoffs_carry_banners() -> None:
    files = [
        "AEGIS_4_PHASE_COMPLETION_STATUS_2026-09-26.md",
        "AEGIS_BACKEND_FRONTEND_STABILIZATION_PLAN_2026-09-25.md",
        "AEGIS_CURRENT_SYSTEM_AUDIT_2026-09-27.md",
        "AEGIS_DEEP_SYSTEM_HEALTH_AUDIT_2026-09-27.md",
        "AEGIS_DEVELOPMENT_HANDOFF_2026-09-18.md",
        "AEGIS_FULL_PRODUCTION_SENSOR_HANDOFF_2026-09-27.md",
        "AEGIS_KERNEL_NIDS_DEEP_HANDOFF_2026-09-27.md",
        "AEGIS_KERNEL_NIDS_PRODUCTION_REANALYSIS_HANDOFF_2026-09-27.md",
        "AEGIS_RECOVERY_HANDOFF_RETURN_TO_NORMAL_2026-09-27.md",
    ]
    for rel in files:
        assert "HISTORICAL (P6-DOC-TRUTH)" in _read(rel), rel


def test_contract_map_has_no_tcp_fallback_and_labels_abi_history() -> None:
    text = _read("CONTRACT_MAP.json")
    assert "non-Windows development uses a loopback TCP fallback" not in text
    assert "no TCP fallback is implemented" in text
    assert "shared/abi/pep_abi.md" in text
    assert "is_final_enforcement=false" in text
    assert "issue #45" in text


def test_release_trust_anchor_points_at_active_candidate() -> None:
    text = _read("docs/gates/RELEASE_TRUST_ANCHOR.md")
    assert "`release/T20-final/466a226`" in text
    assert "release\\T20-final\\466a226" in text
    assert "`release/T20-final/b597e71`" not in text
    assert "release\\T20-final\\b597e71" not in text
    assert "`b597e71` (superseded by `466a226`)" in text


def test_readme_and_interview_split_coverage_claims() -> None:
    readme = _read("README.md")
    assert "| Evaluable in the runtime | 23/23 |" not in readme
    assert "| Host-evaluable | 22/23 |" in readme
    interview = _read("docs/portfolio/INTERVIEW_PREP.md")
    assert "catalog and evaluable coverage" not in interview
    assert "host-evaluable\ncoverage (R2003/FN-1)" in interview
    assert "All 23 rules are live-proven" in interview
    assert "host-evaluable 22/23" in interview
    catalog = _read("docs/portfolio/DETECTION_CATALOG.md")
    assert "`APPLY_NOW.md` mentions ATT&CK only as an ATS keyword" not in catalog


def test_zero_loss_wording_has_recorded_window() -> None:
    text = _read("docs/portfolio/RESUME_PROJECT.md")
    assert "and zero-loss counters." not in text
    assert "zero loss/shed counters were measured only in that recorded window" in text
    assert "later lab snapshots show nonzero ring/alert-write counters" in text


def test_adr_and_lifecycle_are_scoped_to_current_truth() -> None:
    adr = _read("docs/adr/0001-architecture-lock.md")
    assert "Accepted — HISTORICAL in part (P6-DOC-TRUTH)" in adr
    assert "core/dispatcher.zig is the ONLY production runtime orchestrator" in adr
    assert "Current-state note (2026-11-24)" in adr
    lifecycle = _read("docs/runtime/LIFECYCLE.md")
    assert "dashboard (Rust)" not in lifecycle
    assert ":8080" not in lifecycle
    assert "dashboard (Python, read-only) ──► 127.0.0.1:5000" in lifecycle
    assert "current state-machine authority is" in lifecycle


def test_application_and_outreach_content_is_removed() -> None:
    quick = _read("docs/portfolio/APPLY_NOW.md")
    for stale in (
        "job application",
        "cold email",
        "recruiter",
        "LinkedIn",
        "Application tracker",
        "ATS keywords",
        "Use this everywhere",
        "30-second pitch",
    ):
        assert stale.lower() not in quick.lower(), stale
    assert "# Technical evidence quick reference" in quick
    assert "detection-only" in quick
    readme = _read("README.md")
    assert "For recruiters and job applications" not in readme
    assert "Ready-to-use job application kit" not in readme
    assert "Technical evidence quick reference" in readme
    architecture = _read("docs/portfolio/ARCHITECTURE_EN.md")
    assert "recruiters, interviewers" not in architecture
    demo = _read("docs/portfolio/DEMO.md")
    assert "recruiter-demo" not in demo
    interview = _read("docs/portfolio/INTERVIEW_PREP.md")
    assert "[Apply now]" not in interview


def test_pep_abi_narrative_is_historical_but_abi_bytes_frozen() -> None:
    text = _read("shared/abi/pep_abi.md")
    assert "HISTORICAL AUTHORITY NARRATIVE (P6-DOC-TRUTH / issue #45)" in text
    assert "detection-only policy/evidence authority" in text
    assert "is_final_enforcement: false" in text
    for marker in (
        "FINAL security authority",
        "ONLY final enforcement authority",
        "Action Dispatcher (block via WFP",
    ):
        for line in text.splitlines():
            if marker in line and not line.lstrip().startswith(">"):
                assert "HISTORICAL" in line, line
    for frozen in (
        "PepRequest is 64 bytes (extern struct, no padding)",
        "PepResponse is 24 bytes (extern struct",
        "PepAssessmentResponse is 16 bytes; host_effect_confirmed is always zero",
        "int aegis_pep_read_events(",
    ):
        assert frozen in text, frozen


def test_doc_checker_accepts_hyphenated_aegisctl_commands() -> None:
    checker = _read("scripts/doc_checker.py")
    doc = _read("docs/CLI_COMMANDS.md")
    cli = _read("tools/aegisctl.py")
    assert checker.count("[a-z_0-9][a-z_0-9-]*") >= 2
    assert "mark-fp" in doc
    assert '"mark-fp"' in cli
    assert 'sub.add_parser("mark-fp"' in checker


def test_source_comments_no_longer_claim_removed_core_paths_or_tcp_fallback() -> None:
    writer = _read("nose/pipe_writer.go")
    golden = _read("nose/canonical_test.go")
    cli = _read("src/tests/cli/nose_pipe_e2e_cli.zig")
    assert "core/nose_pipe_reader.zig" not in writer
    assert "core/nose_pipe_e2e_cli.zig" not in cli
    assert "core/canonical_event.zig" not in golden
    assert "src/capture/nose_pipe_reader.zig" in writer
    assert "src/contract/canonical_event.zig" in golden
    assert "capture/nose_pipe_reader.zig" in cli
    assert "src/tests/cli/nose_pipe_e2e_cli.zig" in cli
    assert "TCP loopback" not in writer
    assert "loopback TCP fallback" not in writer
    assert "useSocket" not in writer
    assert "no TCP fallback is implemented" in writer
    assert "no TCP fallback" in writer
