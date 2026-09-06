# G13 — Forensics + Replay

**Gate:** G13
**Status:** PARTIAL (JSONL logging exists; no replay engine)
**Date:** 2026-09-07

## Requirement
```
ทุก enforcement ต้องตอบได้:
ใครตัดสิน? ตัดสินจาก event ไหน? ใช้ policy version ไหน?
ใช้ evidence อะไร? PEP action อะไร? ผลลัพธ์คืออะไร?
```

## Current State
- `logs/anomalous.json` — JSONL append-only alert log
- `bridgeStatusReporter` prints stats every 30s
- G10 PEP returns `PepResult` with `audit_logged` field

## Forensic Record Design
```json
{
  "forensic_id": 1,
  "timestamp_ms": 1725700000000,
  "event_id": 42,
  "decision_authority": "policy-v1",
  "policy_version": 1,
  "evidence": {
    "rule_id": 10,
    "rule_name": "SQL Injection",
    "tier": 1,
    "confidence": 95
  },
  "pep_action": "Block",
  "pep_result": {
    "success": true,
    "source_ip": "192.168.1.1"
  },
  "flow_id": 1283,
  "rollback_info": {
    "can_rollback": true,
    "rollback_action": "unblock_ip"
  }
}
```

## Replay Design
- Load historical events from JSONL
- Re-run through detection engine with specified policy version
- Compare results with original enforcement

## Exit Gate
```
[x] Forensic record design documented
[x] PepResult.audit_logged tracks enforcement audit
[x] logs/anomalous.json provides append-only evidence trail
[ ] Structured forensic record (JSON schema above)
[ ] Replay engine implementation
```
