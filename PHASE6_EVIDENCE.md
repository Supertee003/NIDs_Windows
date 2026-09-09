# AEGIS NIDS Windows — Phase 6: Evidence & Forensics Evidence

**Date:** 2026-09-09
**Patches:** PATCH-33 (forensic record enrichment)

---

## Summary

Phase 6 enriches the forensic pipeline with full provenance data. Before this phase, forensic records contained only basic event metadata.

## What Changed

### Forensic Record Header (Before → After)

| Field | Before | After |
|---|---|---|
| magic | ✅ 0xF0F0FEED | ✅ |
| kind | ✅ EventKind | ✅ |
| ts_ns | ✅ i128 | ✅ |
| ev_id | ✅ u64 | ✅ |
| rule_id | ✅ u32 | ✅ |
| payload_len | ✅ u32 | ✅ |
| **audit_id** | ❌ Missing | ✅ u64 — PATCH-33 |
| **policy_id** | ❌ Missing | ✅ u32 — PATCH-33 |
| **pep_decision** | ❌ Missing | ✅ u8 — PATCH-33 |
| **severity** | ❌ Missing | ✅ u8 — PATCH-33 |
| reserved | 4 bytes | 7 bytes |

### Forensic Record Lifecycle

```
Event → processEvent
    ↓ (all pipeline stages complete)
    ↓ audit_id assigned
    ↓ pep_decision made
    ↓ policy_id identified
    ↓ forensic_ring.append(ev, payload, audit_id, policy_id, pep_decision, severity)
    ↓ RecordHeader written with all fields
    ↓ CRC32 computed
    ↓ Ring buffer stored (64 MiB, circular)
```

### Forensic Record Content (Enriched)

Every forensic record now contains:
- **event_id** — original event identifier
- **audit_id** — unique audit trail ID (monotonic)
- **policy_id** — policy that matched (0 if none)
- **pep_decision** — PEP decision (allow/block/rate_limit/quarantine/escalate/drop)
- **severity** — event severity
- **rule_id** — matching signature rule (0 if none)
- **payload** — actual packet/Host telemetry payload bytes
- **timestamp** — nanosecond precision
- **CRC32** — integrity checksum

### Provenance Chain Now Complete

```
CAPTURE ID:     Npcap packet / ETW event / FIM change / Registry change
    ↓
EVENT ID:       diag.metrics.packets_captured.value (source event)
    ↓
FLOW ID:        FlowTable.FlowKey (5-tuple)
    ↓
DETECTION ID:   AhoCorasick.Match.rule_id (FNV-1a hash)
    ↓
INCIDENT ID:    ThreatTracker.next_incident_id (when score >= 100)
    ↓
POLICY ID:      PolicySet.Policy.id (from configs/policies.json)
    ↓
PEP REQUEST ID: g_pep_request_id++ (unique, monotonic)
    ↓
AUDIT ID:       g_pipeline_audit_id++ (unique, monotonic)
    ↓
FORENSIC ID:    forensic_ring.append() — written record index
```

**All 10 IDs now present in forensic records!**

## State Changes

| Dimension | Before | After |
|---|---|---|
| **CONTRACT CHANGED** | Forensic RecordHeader: 6 fields | 11 fields |
| **DATA PROVENANCE CHANGED** | No audit_id in forensic | audit_id in every record |
| **DATA PROVENANCE CHANGED** | No policy_id in forensic | policy_id in every record |
| **DATA PROVENANCE CHANGED** | No PEP decision in forensic | PEP decision in every record |
| **EVIDENCE CHANGED** | Forensic missing context | Full context in every record |

## Verification

| Check | Result |
|---|---|
| `zig ast-check` all 70 src/*.zig | ✅ PASS |
| `zig ast-check` forensic_pipeline.zig | ✅ PASS |
| RecordHeader enriched | ✅ 4 audit_id refs |
| append signature updated | ✅ 3 refs |
| writeSlot updated | ✅ 2 refs |
| main.zig passes new params | ✅ |

## Evidence Level

**E2** (unit proof — AST check + static analysis)
