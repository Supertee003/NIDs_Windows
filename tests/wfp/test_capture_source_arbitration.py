"""PHASE-6: network acquisition arbitration contract pins.

Two acquisition sources exist (Npcap via Go Nose, WFP kernel ring). Running
both as detection ingress duplicates rows; running only one leaves a known
blind spot. The system must therefore state WHICH source owns ingress, in
which state, and make the shadowed rows countable.

These are static source pins (E1): the arbiter's behavioral proof is the
Zig unit suite (E2), and the host-mode switch is operator evidence (E5).
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ARBITER = REPO_ROOT / "src" / "capture" / "source_arbiter.zig"
TELEMETRY = REPO_ROOT / "src" / "capture" / "wfp_telemetry.zig"
RUNTIME_STATE = REPO_ROOT / "src" / "pipeline" / "runtime_state.zig"
HANDLERS = REPO_ROOT / "src" / "control" / "handler_registry.zig"
DOC = REPO_ROOT / "docs" / "WFP_IOCTL_STATUS.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def test_arbiter_states_are_explicit_and_named() -> None:
    text = _read(ARBITER)
    for mode in (
        "undecided",
        "npcap_primary",
        "kernel_fallback",
        "split_lab",
        "none",
    ):
        assert f"{mode} = " in text
    # The control plane renders names, never a bare ordinal.
    assert "pub fn modeName" in text
    assert "pub fn reasonName" in text


def test_kernel_takeover_requires_kernel_evidence_and_a_stall_window() -> None:
    text = _read(ARBITER)
    assert "STALL_MS" in text
    # Both halves of the rule must be present: rows seen while Nose is
    # idle AND time elapsed. Idleness alone must never flip the mode.
    assert "kernel_rows_while_nose_idle" in text
    assert "kernel_rows_while_nose_idle > 0" in text
    assert "(in.now_ms - self.last_nose_progress_ms) >= STALL_MS" in text


def test_split_mode_is_opt_in_and_lab_only() -> None:
    text = TELEMETRY.read_text(encoding="utf-8", errors="ignore")
    assert "AEGIS_CAPTURE_SPLIT" in text
    # Default must be off: one acquisition authority unless explicitly told
    # the interfaces are disjoint.
    assert "catch return false" in text


def test_telemetry_drains_but_shadows_when_packet_path_owns_ingress() -> None:
    text = _read(TELEMETRY)
    assert "source_arbiter.Arbiter" in text
    assert "arbiter.evaluate" in text
    assert "!d.kernel_may_submit" in text
    assert "g_wfp_shadow_rows.fetchAdd(1" in text
    # A shadowed record must never reach the pipeline; only the draining
    # advance continues. And the shadow branch must precede submitRecord.
    shadow = text.index("!d.kernel_may_submit")
    assert shadow < text.index("else if (submitRecord(rec))")
    # A stalled takeover still keeps Nose's own rows admissible.
    assert ".packet_may_submit = true, .kernel_may_submit = true" in _read(ARBITER)


def test_runtime_state_carries_arbitration_for_the_control_plane() -> None:
    text = _read(RUNTIME_STATE)
    for field in ("g_capture_mode", "g_capture_reason", "g_wfp_shadow_rows"):
        assert field in text


def test_queue_stats_states_mode_reason_and_shadow_rows() -> None:
    text = _read(HANDLERS)
    assert 'mode\\":' in text
    assert 'reason\\":' in text
    assert 'shadow_rows\\":' in text
    assert "kernel_owned" in text


def test_docs_name_the_acquisition_states() -> None:
    text = _read(DOC)
    for mode in ("npcap_primary", "kernel_fallback", "split_lab"):
        assert mode in text
    assert "shadow" in text.lower()
