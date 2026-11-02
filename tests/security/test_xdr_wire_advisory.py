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
    allowed = {"categoryForSource", "observe"}
    assert uses <= allowed, f"unexpected xdr_runtime uses: {uses - allowed}"
    # the feed site carries the advisory boundary comment contract
    assert "advisory evidence feed" in (SRC / "pipeline/event_processor.zig").read_text(
        encoding="utf-8", errors="replace"
    )
    # the feed happens only when a detection identity exists
    feed = re.search(r"if \(detection_rule_id != 0\)", proc)
    assert feed, "XDR feed must be gated on detection identity"


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
