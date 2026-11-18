"""XDR-WIRE-001 advisory boundary pins.

Owner decision (2026-11-02): XDR enters the runtime as advisory,
read-only evidence ONLY. These E2 pins fail if anyone wires the XDR
fabric into the product's decision/effect path.

Checks against live source (they are the machine check of the owner
decision recorded in docs/ai-context/10-current-phase.md):
  P1. xdr_runtime.zig imports no decision/enforcement/state authority.
  P2. event_processor touches xdr_runtime only through the advisory
      observe/category accessors, and never passes XDR output to
      policy/PEP/DEFCON/fate.
  P3. The control-plane contract for xdr.list is read-role,
      non-mutation, no postcondition.
  P4. The runtime spine manifest pin still rejects XDR modules
      (evidence-only modules must not claim runtime-spine authority).
  P5. The XDR runtime module stays in the canonical Zig test graph.
  P6. The recording-only receipt bridge imports no decision/effect authority.
  P8. The host TCP table adapter (XDR-005-A) is observe-only.
  P9. xdr.verify (XDR-005-B) is read-only persisted-snapshot replay.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
assert (REPO / "AGENTS.md").exists(), f"bad repo root: {REPO}"

SRC = REPO / "src"


def body(rel: str) -> str:
    text = (SRC / rel).read_text(encoding="utf-8", errors="replace")
    # strip line comments so historical notes cannot false-positive
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


FORBIDDEN_XDR_RUNTIME_IMPORTS = [
    "policy_ir",
    "pep_bindings",
    "action_dispatcher",
    "defcon",
    "runtime_state",
    "tier3_state",
    "forensic_pipeline",
]


def test_p1_xdr_runtime_imports_no_authority():
    src = body("xdr/xdr_runtime.zig")
    for needle in FORBIDDEN_XDR_RUNTIME_IMPORTS:
        assert f'@import("{needle}' not in src, f"xdr_runtime must not import {needle}"


def test_p2_event_processor_feeds_only_the_advisory_surface():
    proc = body("pipeline/event_processor.zig")
    # every xdr_runtime use is an advisory accessor (paren = call site;
    # the import path `xdr_runtime.zig` must not count as a call)
    uses = set(re.findall(r"xdr_runtime\.(\w+)\s*\(", proc))
    allowed = {
        "categoryForSource",
        "observeEvent",
        "observeHostObservation",
        "noteReceiptRecorded",
        "noteReceiptFailed",
        "noteReceiptSkipped",
    }
    assert uses <= allowed, f"unexpected xdr_runtime uses: {uses - allowed}"
    # the feed site carries the advisory boundary comment contract
    assert "advisory evidence feed" in (SRC / "pipeline/event_processor.zig").read_text(
        encoding="utf-8", errors="replace"
    )
    # XDR-005-A semantic gate: detection identity OR the exact host socket
    # observation tuple. The host branch must be the narrow pending gate and
    # must never run when a detection identity exists.
    feed = re.search(r"if \(detection_rule_id != 0 or host_obs\)", proc)
    assert feed, "XDR feed must be gated on detection identity or host observation"
    assert "if (host_obs and detection_rule_id == 0)" in proc
    assert "observeHostObservation(" in proc
    pred = re.search(r"fn isXdrHostSocketObservation\(.*?\n\}", proc, re.S)
    assert pred, "host socket admission predicate missing"
    pred_body = pred.group(0)
    assert "ev.source == .capture_host_net" in pred_body
    assert "ev.kind == .host_socket_observed" in pred_body
    assert "ev.rule_id == 0" in pred_body
    assert "(ev.src_ip != 0 or src6 != null)" in pred_body
    # XDR-RECEIPT-002: the receipt helper is recording-only. It may call the
    # evidence bridge and counters, but no policy/PEP/DEFCON/dispatch surface.
    helper = re.search(r"fn recordXdrAdvisoryReceipt\(.*?\n\}", proc, re.S)
    assert helper, "recording-only XDR receipt helper missing"
    receipt_body = helper.group(0).lower()
    for forbidden in ("policy", "pep", "defcon", "dispatch", "enforce"):
        assert forbidden not in receipt_body, f"XDR receipt helper touches {forbidden}"
    # the pipeline discards the receipt value; it never branches on it
    assert "_ = recordXdrAdvisoryReceipt(" in proc


def test_p3_xdr_list_contract_is_read_only():
    proto = (SRC / "control/protocol.zig").read_text(encoding="utf-8", errors="replace")
    spec = re.search(
        r"\.xdr_list\s*=>\s*\.\{([^}]+)\}", proto
    )
    assert spec, "xdr.list protocol spec missing"
    spec_body = spec.group(1)
    assert "required_role = .read" in spec_body
    assert ".is_mutation = false" in spec_body
    assert ".has_postcondition = false" in spec_body
    assert "never a host action" in spec_body

    reg = body("control/handler_registry.zig")
    assert "registerHandler(.xdr_list, handlers.xdrList)" in reg
    handler = re.search(r"fn xdrList\(.+?\n(.+?)\n    \}", reg, re.S)
    assert handler and "listJson" in handler.group(1)
    assert "pep" not in handler.group(1).lower()
    assert "enforcement" not in handler.group(1).lower()


def test_p4_runtime_spine_pin_intact():
    spine = (SRC / "contract/runtime_spine.zig").read_text(
        encoding="utf-8", errors="replace"
    )
    assert 'std.mem.eql(u8, module.name, "xdr_incident_fabric")' in spine
    assert 'std.mem.eql(u8, module.name, "xdr_harden_integration")' in spine
    # and the manifest builder keeps has_xdr out of the spine claim
    manifest = (SRC / "contract/runtime_manifest.zig").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "has_xdr" in manifest  # flag exists but is never spined


def test_p5_new_module_in_zig_test_graph():
    scope = (REPO / "src/all_tests.zig").read_text(encoding="utf-8", errors="replace")
    assert "_ = @import(\"xdr/xdr_runtime.zig\");" in scope


def test_p8_host_net_stays_evidence_only():
    # XDR-005-A: the host TCP table adapter is observe-only. It may import
    # the event contract, never policy/PEP/DEFCON/dispatch/runtime authority.
    src = body("windows/host_net.zig")
    for needle in (
        "policy_ir",
        "pep_bindings",
        "action_dispatcher",
        "defcon",
        "tier3_state",
        "runtime_state",
        "forensic_pipeline",
    ):
        assert f'@import("{needle}' not in src, f"host_net must not import {needle}"
    # The only Win32 import is the read-only table query.
    assert 'GetExtendedTcpTable' in src
    assert 'DynLib.open("iphlpapi.dll")' in src
    for needle in ("WriteProcessMemory", "CreateRemoteThread", "TerminateProcess", "send("):
        assert needle not in src
    # Host observations carry no detection identity by construction.
    assert "ev.rule_id = 0" in src
    # The daemon wires it outside the readiness barrier behind its kill switch.
    daemon = body("daemon.zig")
    assert "host_net.initFromEnv()" in daemon
    assert "telemetry.hostNetThread" in daemon


def test_p9_xdr_verify_is_read_only_replay():
    # XDR-005-B: the replay verification surface must stay READ/read-only and
    # must never write the ring or reach decision/effect authority.
    proto = (SRC / "control/protocol.zig").read_text(encoding="utf-8", errors="replace")
    assert "xdr_verify = 511" in proto
    assert '"xdr.verify"' in proto
    spec = re.search(r"\.xdr_verify\s*=>\s*\.\{([^}]+)\}", proto)
    assert spec, "xdr.verify protocol spec missing"
    spec_body = spec.group(1)
    assert "required_role = .read" in spec_body
    assert ".is_mutation = false" in spec_body
    assert ".has_postcondition = false" in spec_body
    assert "never a host action" in spec_body

    reg = body("control/handler_registry.zig")
    assert "registerHandler(.xdr_verify, handlers.xdrVerify)" in reg
    handler = re.search(r"fn xdrVerify\((.+?)\n    \}", reg, re.S)
    assert handler, "xdr.verify handler missing"
    handler_body = handler.group(1)
    assert "xdr_evidence_flow.replayRecord(" in handler_body
    assert "receipt tokens are not persisted" in handler_body
    # Read-only: no ingest, no enforcement, no ring append, no receipt issue.
    for needle in (
        "observeEvent(",
        "observeHostObservation(",
        "policy_ir",
        "pep_bindings",
        "action_dispatcher",
        "defcon",
        "tier3_state",
        "ring.append(",
        "ring.appendReceipt(",
        "recordAssessment(",
    ):
        assert needle not in handler_body, f"xdr.verify handler must not call {needle}"
    # Post-hoc replay proves record replay integrity, not token issuance.
    flow = body("xdr/xdr_evidence_flow.zig")
    assert "pub fn replayRecord(" in flow
    assert "fn replaySlot(" in flow

    cli = (REPO / "tools/aegisctl.py").read_text(encoding="utf-8", errors="replace")
    assert '"xdr.verify"' in cli
    assert '"xdr.list"' in cli
    doc = (REPO / "shared/protocol/control_protocol.md").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "| `xdr.verify` | READ | no |" in doc


def test_p6_xdr_receipt_bridge_is_recording_only():
    flow = body("xdr/xdr_evidence_flow.zig")
    for needle in (
        "policy_ir",
        "pep_bindings",
        "action_dispatcher",
        "defcon",
        "tier3_state",
    ):
        assert f'@import("{needle}' not in flow, f"xdr_evidence_flow must not import {needle}"
    assert "ids_evidence_receipt" in flow
    assert "recordAssessment" in flow
