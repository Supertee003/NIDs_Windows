"""BE-EVI-097: the NDJSON evidence contract writer <-> readers agree.

Failure mode pinned: the daemon never wrote logs/aegis_core.ndjson
while the whole frontend fleet tailed it (dark surfaces showing SAFE),
and the legacy writer schema lacked every receipt key readers gate on
(no confirmed block could ever validate from a file line). Contract:

  AC1. The daemon projects detections: forensic_log is initialized in
       daemon.zig (env-gated), processEvent emits per detection, and
       dispatchWithReceipt returns the confirmed verdict gating the
       enforced claim.
  AC2. The writer emits every key readers gate on (identity + receipt).
  AC3. A writer-format enforced line validates end to end through the
       web incident path (receipt_valid + BLOCKED_CONFIRMED); an
       observed line stays OBSERVED and never validates.
  AC4. forensic_log tests execute (wired into all_tests.zig — the 5th
       silent-death catch of that registry's class).

No tree writes: the web path is driven with in-memory records only.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

WRITER = (REPO_ROOT / "src" / "forensic" / "forensic_log.zig").read_text(encoding="utf-8")
DAEMON = (REPO_ROOT / "src" / "daemon.zig").read_text(encoding="utf-8")
PROCESSOR = (REPO_ROOT / "src" / "pipeline" / "event_processor.zig").read_text(encoding="utf-8")
DISPATCHER = (REPO_ROOT / "src" / "policy" / "action_dispatcher.zig").read_text(encoding="utf-8")


def test_daemon_projects_detections_to_the_evidence_log():
    assert "forensic_log.init()" in DAEMON
    assert 'forensic_log.zig").shutdown()' in DAEMON
    assert "AEGIS_EVIDENCE_LOG" in DAEMON
    assert "g_evidence_log_enabled" in DAEMON
    assert "evidenceLog(" in PROCESSOR
    assert "matched_rule_id != 0" in PROCESSOR


def test_enforced_claim_is_gated_on_the_dispatch_verdict():
    assert "pub fn dispatchWithReceipt(" in DISPATCHER
    assert ") bool {" in DISPATCHER
    assert "confirmed_effect = dispatcher.ActionDispatcher.dispatchWithReceipt(" in PROCESSOR


def test_writer_emits_every_key_readers_gate_on():
    # Zig format strings escape quotes (\"key\":) — match the emission
    # pattern, not bare words (comments mention these names too).
    for key in (
        "ts_ms", "mono_ns", "level", "event", "rule",
        "src_ip", "src_port", "session_id", "payload_len",
        "policy", "policy_id", "event_id", "trace_id", "audit_id",
        "enforcement_status", "host_effect_confirmed",
        "filter_id", "request_id", "decision", "provider",
        "receipt_version",
    ):
        assert '\\"' + key + '\\":' in WRITER, f"writer never emits {key}"


def test_writer_tests_execute_in_the_unit_binary():
    closure = (REPO_ROOT / "src" / "all_tests.zig").read_text(encoding="utf-8")
    assert "forensic/forensic_log.zig" in closure


def test_confirmed_quarantine_is_its_own_observable_event():
    """RB-013: a receipt-verified quarantine must be distinguishable from a
    block in the persisted NDJSON, not folded into decision=block."""
    assert "evidenceEventName(" in PROCESSOR
    assert "evidenceDecisionLabel(" in PROCESSOR
    assert "evidenceConfirmationMarker(" in PROCESSOR
    assert '"action_quarantine"' in PROCESSOR
    assert '"QUARANTINED_CONFIRMED"' in PROCESSOR


def test_confirmed_quarantine_reaches_a_persisted_diagnostic_stream():
    """RB-013 (G2-RB013-LOG): the receipt-verified quarantine must survive in
    a persisted diagnostic stream, not stderr alone. The dispatcher names the
    PEP confirmation explicitly and the daemon tees the diagnostic stream
    into a file sink, so service mode leaves the confirmation lines on disk.
    The zig unit tests (src/core/diagnostics.zig, src/daemon.zig, pulled into
    the test graph via all_tests.zig) prove the sink behavior at E2."""
    assert 'diag.info("pep=quarantine confirmed=true filter_id={d}"' in DISPATCHER
    daemon = (REPO_ROOT / "src" / "daemon.zig").read_text(encoding="utf-8")
    assert "installDiagnosticFileSink" in daemon
    assert "TeeSink.init(diag.StderrSink.init()" in daemon
    all_tests = (REPO_ROOT / "src" / "all_tests.zig").read_text(encoding="utf-8")
    assert '@import("daemon.zig")' in all_tests


def test_quarantine_receipt_passes_the_operator_contract():
    from tools.aegisctl.contracts import validate_enforcement_receipt

    receipt = {
        "request_id": 404,
        "event_id": 401,
        "policy_id": 3,
        "trace_id": 402,
        "audit_id": 403,
        "decision": "quarantine",
        "status": "enforced",
        "provider": "wfp",
        "host_effect_confirmed": True,
        "filter_id": 78056,
        "receipt_version": 1,
    }
    ok, errors = validate_enforcement_receipt(receipt)
    assert ok, errors


ENFORCED_LINE = {
    "ts_ms": 1791296893400,
    "mono_ns": 1,
    "level": "critical",
    "event": "signature_match",
    "rule": "4237725842",
    "src_ip": "192.168.1.100",
    "src_port": 1234,
    "session_id": 7,
    "payload_len": 3,
    "policy": "block",
    "policy_id": 4,
    "event_id": 201,
    "trace_id": 202,
    "audit_id": 203,
    "enforcement_status": "enforced",
    "host_effect_confirmed": True,
    "filter_id": 301,
    "request_id": 302,
    "decision": "block",
    "provider": "wfp",
    "receipt_version": 1,
}

QUARANTINE_LINE = dict(
    ENFORCED_LINE,
    event="action_quarantine",
    policy="quarantine",
    decision="quarantine",
    policy_id=5,
)


OBSERVED_LINE = {
    "ts_ms": 1791296893401,
    "level": "warn",
    "event": "signature_match",
    "rule": "1",
    "src_ip": "10.0.0.1",
    "policy": "alert",
    "enforcement_status": "observed",
    "host_effect_confirmed": False,
    "filter_id": 0,
    "request_id": 0,
}


def test_writer_enforced_line_validates_end_to_end():
    from tools.aegisctl.web_dashboard import app as dashboard

    incident = dashboard._record_to_incident(dict(ENFORCED_LINE))
    assert incident["receipt_valid"] is True
    assert incident["status"] == "BLOCKED_CONFIRMED"
    assert incident["rule_id"] == "4237725842"
    assert incident["src_ip"] == "192.168.1.100"


def test_writer_quarantine_line_is_not_reported_as_a_block():
    from tools.aegisctl.web_dashboard import app as dashboard

    incident = dashboard._record_to_incident(dict(QUARANTINE_LINE))
    assert incident["receipt_valid"] is True
    assert incident["status"] == "QUARANTINED_CONFIRMED"
    assert incident["decision"] == "quarantine"


def test_threat_posture_counts_blocks_and_quarantines_separately():
    from tools.aegisctl.web_dashboard import app as dashboard

    incidents = [
        dashboard._record_to_incident(dict(ENFORCED_LINE)),
        dashboard._record_to_incident(dict(QUARANTINE_LINE)),
    ]
    threat = dashboard._threat_posture(incidents)
    assert threat["confirmed_blocks"] == 1
    assert threat["confirmed_quarantines"] == 1
    assert threat["confirmed_effects"] == 2


def test_unconfirmed_quarantine_never_claims_confirmed_status():
    from tools.aegisctl.web_dashboard import app as dashboard

    line = dict(QUARANTINE_LINE, host_effect_confirmed=False)
    incident = dashboard._record_to_incident(line)
    assert incident["receipt_valid"] is False
    assert incident["status"] == "PEP_UNVERIFIED"


def test_writer_observed_line_never_claims_enforcement():
    from tools.aegisctl.web_dashboard import app as dashboard

    incident = dashboard._record_to_incident(dict(OBSERVED_LINE))
    assert incident["receipt_valid"] is False
    assert incident["status"] not in (
        "ENFORCED", "BLOCKED", "BLOCKED_CONFIRMED", "QUARANTINED_CONFIRMED"
    )
