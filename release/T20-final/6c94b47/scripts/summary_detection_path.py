#!/usr/bin/env python3
"""HISTORICAL WORK ITEM 9 snapshot — detection -> decision -> policy + evidence.

P4-RUNTIME-TRUTH (2026-11-24): the original print-only summary carried
current-sounding WFP-enforcement and "GAP ... CLOSED" claims that do not hold
for the detection-only product. Those lines are relabelled HISTORICAL below;
the evidence count is read from EVIDENCE_INDEX.json so it cannot go stale
again. This script has no runtime effect and is not a release gate.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _evidence_line() -> str:
    try:
        index = json.loads((ROOT / "EVIDENCE_INDEX.json").read_text(encoding="utf-8"))
        count = len(index.get("evidence", []))
        return (
            f"   EVIDENCE_INDEX.json        : {count} recorded entries (E0-E7); "
            "each entry carries its own head_sha — historical entries are not "
            "current-HEAD proof"
        )
    except (OSError, ValueError) as exc:
        return f"   EVIDENCE_INDEX.json        : unreadable ({exc})"


print("WORK ITEM 9 (HISTORICAL SNAPSHOT): Detection -> Decision -> Policy + Evidence")
print("=" * 70)
print("The product is detection-only: no host effect, no WFP mutation, no enforcement.")
print("The labels below describe a historical design snapshot, not current truth.")

print("\n1. DETECTION ENGINES (as recorded in the historical snapshot)")
engines = [
    "signature_engine.zig: Aho-Corasick based signature matching",
    "correlator.zig               : Event correlation across sessions/streams",
    "anomaly_detector.zig         : Anomaly detection on flows",
    "threat_tracker.zig           : Threat incident creation and tracking",
    "threat_intel.zig             : Threat intelligence enrichment",
    "proto_anomaly.zig            : Protocol anomaly detection",
    "injection_detector.zig       : Injection attack detection",
    "ml_detector.zig              : Machine learning based detection",
    "rag_engine.zig               : Regex+AN anomaly detection",
    "fast_scan.pyx                : Cython fast scan (Tier-2)",
]
for e in engines:
    print("   %s" % e)

print("\n2. CORRELATION & TRACKING (as recorded)")
print("   correlator.zig      : Session/event correlation")
print("   threat_tracker.zig  : Incident creation and tracking")
print("   verdict_aggregator.zig: Verdict aggregation from multiple sources")

print("\n3. POLICY IR PIPELINE (as recorded)")
print("   policy_engine.zig          : Policy engine with IR execution")
print("   pep_bindings.zig       : PEP integration bindings")
print("   dispatcher.zig       : Policy dispatch and phase management")
print("   dispatcher_phase_b.zig: Policy phase B")
print("   policy_signing.zig   : Policy signature verification")
print("   wfp_production.zig   : HISTORICAL WFP path; not on the production import graph")

print("\n4. DETECTION -> DECISION -> POLICY PATH (historical integration diagram)")
print("   CanonicalEvent")
print("      (named pipe C ABI)")
print("   Flow Table (flow_table.zig)")
print("   Signature Engine (signature_engine.zig)")
print("   Correlation (correlator.zig)")
print("   Threat Tracker (threat_tracker.zig) -> Incident creation")
print("   Policy IR (policy_engine.zig)")
print("   PEP Request (via Rust PEP FFI)")
print("   PEP evidence receipt (detection-only; no host effect)")

print("\n5. EVIDENCE VERIFICATION (historical labels)")
print(_evidence_line())
print("   FOR-001                : Forensic integrity — hash chain validation (EVT-002)")
print("   FOR-002                : Detection completeness — event -> detection mapping (EVT-003)")
print("   FOR-003                : Traceability chain — Incident -> Event -> Decision -> Policy -> PEP -> Forensic (EVT-037)")
print("   FOR-004                : HISTORICAL bridge-test claim (EVT-038); NOT current host proof")
print("   GAP-001                : HISTORICAL Ed25519 / SHA-256 KAT record (EVT-024)")
print("   GAP-002                : HISTORICAL — WFP enforcement was never host-verified (EVT-026)")
print("   GAP-003                : HISTORICAL forensic concurrency record (EVT-008)")
print("   GAP-005                : HISTORICAL driver-implementation record (EVT-025); not a host-effect claim")
print("   GAP-007                : HISTORICAL — shield quarantined; PEP migration slice")
print("   GAP-011                : HISTORICAL — quarantined WFP path is not in the production import graph")

print("\n6. INTEGRATION TESTS (as recorded at E3)")
print("   E3-001  : CanonicalEvent -> nose_contract round-trip")
print("   E3-002  : Batch events -> FIFO order preservation")
print("   E3-003  : Event -> policy_ir evaluate produces action")
print("   E3-004  : Detection -> threat_tracker creates incident")
print("   E3-005  : Forensic ring append -> read -> hash chain intact")
print("   E3-006  : Tier-3 state gates evidence verdicts (no host effect)")
print("   E3-007  : PEP detection-only mode returns allow")
print("   E3-008  : Full golden path — event -> detection -> forensic record (DEFINITIVE)")

print("\n7. SYSTEM VERIFICATION (current commands; run them, do not infer a result)")
print("   zig build              : build the canonical Zig runtime")
print("   python tools/truth.py verify  : TRUTH_VALID (build-source maps)")
print("   python tools/ci_coverage.py  : required gate semantics")

print("\nCONCLUSION (HISTORICAL WORK-ITEM SNAPSHOT): the detection -> decision ->")
print("policy integration was recorded as complete in Zig. This script is a label")
print("correction only. See EVIDENCE_INDEX.json and the current-head audit artifacts")
print("for what is actually verified; no current E4/E5 or host claim is made here.")
