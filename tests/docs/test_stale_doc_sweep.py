"""STALE-DOC-SWEEP pins (2026-10-19): doc <-> source parity guards.

These are documentation-drift guards, not runtime tests. They pin the
docs swept in the STALE-DOC-SWEEP slice to the CURRENT source truth:

- docs/CLI_COMMANDS.md must list exactly the top-level commands the
  parser accepts (no phantom commands, no missing ones) and must not
  reference the quarantined ``tools/aegisctl/commands/`` package as if
  it were live.
- docs/WFP_IOCTL_STATUS.md / docs/PEP_QUARANTINE_STATUS.md must describe
  the current enforcement state (read-only Zig telemetry bridge by
  PEP-001, driver IOCTLs, Rust PEP authority, QUAR-RCPT-112 quarantine)
  and must not point at dead ``core/`` paths.
- .analysis/security.md + .analysis/control.md are point-in-time reviews:
  they must stay marked HISTORICAL and must not claim to be
  "current HEAD".
- docs/runtime/COMPONENT_MATRIX.md / LOCAL_RUNBOOK.md must not describe
  the removed axum :8080 dashboard; they are bannered HISTORICAL.
- docs/DEPLOYMENT.md build/install facts must match build_truth.json
  (aegis_nids.exe, no ``cd core``, AegisNids service).
- CONTRACT_MAP.json must carry the wire v2 contract.
- tools/release_candidate.py release-note text must not carry the dead
  core/ paths.
- EVIDENCE_INDEX.json must carry the V6-FLOW-036 / V6-DETECT-037
  traceability entries and the last_updated_at stamp.
- docs/USER_OPERATIONS_GUIDE.md must not advertise the fail-closed
  ``policy enable/disable/reload`` commands; it must point at the
  operator-state disabled file plus ``rules reload`` (LEFTOVER-SWEEP).
- src/contract/runtime_spine.zig is a spec/proof registry, not a
  production loader: the header must say so, and src/main.zig /
  src/daemon.zig must stay free of it (LEFTOVER-SWEEP).

Read-only: no tree writes.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def _head_block(text: str, lines: int = 15) -> str:
    return "\n".join(text.splitlines()[:lines])


def _parser_top_level_commands() -> set[str]:
    proc = subprocess.run(
        [sys.executable, str(REPO / "tools" / "aegisctl.py"), "--help"],
        cwd=REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=90,
    )
    assert proc.returncode == 0, proc.stderr
    # argparse renders the subcommand choices inside {braces}; the choices
    # block may wrap across lines, so allow whitespace inside the braces.
    for chunk in re.findall(r"\{([a-z0-9,\-\s]+)\}", proc.stdout):
        names = {n for n in re.split(r"[,\s]+", chunk.strip()) if n}
        if "status" in names:
            return names
    raise AssertionError("could not locate the top-level command set in --help")


def _doc_cli_commands(doc: str) -> set[str]:
    return set(re.findall(r"^python tools/aegisctl\.py ([a-z][a-z0-9\-]*)\s*$", doc, re.M))


def test_cli_commands_doc_lists_exactly_the_parser_commands():
    doc = _read("docs/CLI_COMMANDS.md")
    doc_cmds = _doc_cli_commands(doc)
    parser_cmds = _parser_top_level_commands()
    missing_in_doc = sorted(parser_cmds - doc_cmds)
    phantom_in_doc = sorted(doc_cmds - parser_cmds)
    assert doc_cmds == parser_cmds, (
        f"CLI_COMMANDS.md out of sync with the parser: "
        f"missing_in_doc={missing_in_doc} phantom_in_doc={phantom_in_doc}"
    )
    assert "tools/aegisctl/commands/" not in doc, (
        "CLI_COMMANDS.md still points at the quarantined commands package path"
    )


def test_wfp_status_doc_matches_current_enforcement_boundary():
    text = _read("docs/WFP_IOCTL_STATUS.md")
    assert "core/" not in text, "WFP doc still references dead core/ paths"
    for marker in (
        "src/policy/wfp_ioctl.zig",  # read-only Zig telemetry bridge (PEP-001)
        "rust-src",                  # sole enforcement authority
        "PEP-001",
        "IOCTL_AEGIS_BLOCK_FLOW",    # driver IOCTL set is live
        "aegis_wfp_user.dll",        # user-mode bridge the PEP loads
    ):
        assert marker in text, f"WFP doc lost current marker: {marker!r}"


def test_pep_quarantine_doc_records_implemented_state():
    text = _read("docs/PEP_QUARANTINE_STATUS.md")
    assert "core/" not in text, "PEP quarantine doc still references dead core/ paths"
    for marker in (
        "QUAR-RCPT-112",
        "rust-src/lib.rs",
        "enforceQuarantineFlow",
        "IMPLEMENTED",
    ):
        assert marker in text, f"PEP quarantine doc lost current marker: {marker!r}"


def test_analysis_reviews_marked_historical():
    for rel in (".analysis/security.md", ".analysis/control.md"):
        text = _read(rel)
        assert "HISTORICAL" in _head_block(text), f"{rel} lost its HISTORICAL banner"
        normalized = text.lower().replace("`", "")
        assert "current head" not in normalized, (
            f"{rel} still claims to be 'current HEAD' after the review HEAD moved"
        )


def test_runtime_docs_drop_removed_axum_dashboard_claims():
    for rel in ("docs/runtime/COMPONENT_MATRIX.md", "docs/runtime/LOCAL_RUNBOOK.md"):
        text = _read(rel)
        low = text.lower()
        assert "axum" not in low, f"{rel} still describes the removed axum dependency"
        assert "8080" not in text, f"{rel} still documents the removed :8080 endpoint"
        assert "HISTORICAL" in _head_block(text), f"{rel} lost its HISTORICAL banner"


def test_deployment_doc_matches_canonical_build_and_service():
    text = _read("docs/DEPLOYMENT.md")
    assert "aegis_nids.exe" in text, "DEPLOYMENT.md must name the canonical runtime binary"
    assert "zig build" in text, "DEPLOYMENT.md must carry the canonical zig build command"
    assert "AegisNids" in text, "DEPLOYMENT.md must name the installed service (AegisNids)"
    assert "cd core" not in text, "DEPLOYMENT.md still sends builders into the dead core/ tree"
    assert "core/" not in text, "DEPLOYMENT.md still references dead core/ paths"


def test_contract_map_knows_wire_v2():
    contract_map = json.loads(_read("CONTRACT_MAP.json"))
    v2 = [
        c
        for c in contract_map.get("supplementary_contracts", [])
        if c.get("id") == "WIRE_PROTOCOL_V2"
    ]
    assert v2, "CONTRACT_MAP.json lacks the WIRE_PROTOCOL_V2 contract entry"
    assert v2[0].get("file") == "shared/protocol/wire_v2.md"


def test_release_notes_carry_no_dead_core_paths():
    text = _read("tools/release_candidate.py")
    assert "core/wfp_production.zig" not in text, (
        "release-candidate KNOWN_LIMITATIONS still names the dead core/ authority path"
    )
    assert "core/control_ipc.zig" not in text, (
        "release-candidate rollback doc still names the dead core/ transport path"
    )


def test_evidence_index_has_v6_traceability_and_metadata_stamp():
    index = json.loads(_read("EVIDENCE_INDEX.json"))
    ids = {e.get("id") for e in index.get("known_gaps", [])}
    assert {"V6-FLOW-036", "V6-DETECT-037"} <= ids, (
        "EVIDENCE_INDEX.json lacks the V6-FLOW-036 / V6-DETECT-037 traceability entries"
    )
    assert index.get("last_updated_at"), (
        "EVIDENCE_INDEX.json lacks the last_updated_at metadata stamp"
    )


def test_operations_guide_does_not_advertise_fail_closed_policy_mutations():
    text = _read("docs/USER_OPERATIONS_GUIDE.md")
    for cmd in ("policy disable", "policy enable", "policy reload"):
        assert f"aegisctl.py {cmd}" not in text, (
            f"USER_OPERATIONS_GUIDE.md still advertises the fail-closed command: {cmd}"
        )
    assert "disabled_rules.json" in text, (
        "USER_OPERATIONS_GUIDE.md must point at the operator-state disabled file"
    )
    assert "rules reload" in text, (
        "USER_OPERATIONS_GUIDE.md must show 'rules reload' as the apply step"
    )
    assert "exit code 4" in text, (
        "USER_OPERATIONS_GUIDE.md must state the fail-closed exit code"
    )


def test_runtime_spine_header_is_spec_proof_not_production_loader():
    text = _read("src/contract/runtime_spine.zig")
    head = _head_block(text, 40)
    for marker in (
        "REGISTRY (specification + proof)",
        "does NOT load this registry",
        "quarantined",
    ):
        assert marker in head, f"runtime_spine header lost its status marker: {marker!r}"
    for rel in ("src/main.zig", "src/daemon.zig"):
        assert "runtime_spine" not in _read(rel), (
            f"{rel} now imports the spine registry - wiring it into production is a "
            f"dedicated-slice decision; update the header + this pin together"
        )
