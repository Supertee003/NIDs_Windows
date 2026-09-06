# G20 — XDR

**Gate:** G20
**Status:** DOCUMENTED (framework designed in Phase 37 + Ext 1-7)
**Date:** 2026-09-07

## Requirement
```
Network evidence + Host evidence + Process evidence + File/Registry evidence +
Threat Intel + Correlation + Policy + Enforcement
→ สร้าง incident เดียวกันและ trace ได้ตั้งแต่ source → action
```

## Current State
- Network detection: Tier-1 Aho-Corasick + Tier-2 regex + Tier-3 Rust (PRODUCTION)
- Host detection: STUB (minifilter_reader.zig, pipe_monitor.zig)
- Process evidence: STUB (no ETW integration)
- File/Registry evidence: STUB (no FIM/RegNotify)
- Threat Intel: NOT IMPLEMENTED
- Correlation: AtomicThreatTracker (G7, wired into inspect_packet)
- Policy: G9 design (Ed25519 signing)
- Enforcement: Rust PEP (G10, FFI entry point)

## XDR Golden Path (end-to-end trace)
```
1. WFP callout captures network packet
2. windows_capture.zig reads from \\.\AegisWfpDevice
3. inspect_packet(data, ctx) — G3 dispatcher
   ├─ flow_table.lookupOrCreate() — G5 flow tracking
   ├─ Rust validate_payload_safety() — Tier-3 evidence (bool)
   ├─ Aho-Corasick match — Tier-1 evidence (rule_id, severity)
   ├─ AtomicThreatTracker.step1_markSuspicious() — G7 correlation
   ├─ send_to_brain() — UDP to Python Brain (Tier-2 evidence)
   └─ If Block: pep_enforce_action(PepDecision{action: Block}) — G10 enforcement
4. PEP executes block (WFP IOCTL_AEGIS_BLOCK_FLOW) — G12
5. Forensic record created — G13

Trace: Incident → Evidence (rule_id + flow_id + tracker_state) → Event IDs → Action (PEP Block)
```

## Integration with Phase 37 Ext 1-7
The mock telemetry source (Phase 37 Ext 1) + scenarios (Ext 2) + enhanced detectors
(Ext 3) + Windows adapters (Ext 4) + ETW real-time (Ext 5) + injection detector
(Ext 7) provide the full XDR detection layer. Combined with the G2 canonical event,
G3 runtime spine, G5 flow state, G7 correlation, and G10 PEP, the XDR path is:

```
Source → Canonical Event → Flow → Detection → Correlation → Policy → PEP → WFP → Forensics
```

## Exit Gate
```
[x] XDR golden path documented (source → action trace)
[x] Network evidence path works (WFP → inspect_packet → detection)
[x] Correlation works (AtomicThreatTracker, G7)
[x] Enforcement authority exists (Rust PEP, G10)
[x] Forensic trail exists (logs/anomalous.json + PepResult.audit_logged)
[ ] Host evidence (ETW/FIM/Registry — G11)
[ ] Process evidence (ETW Thread/VM hooks — Ext 7)
[ ] Threat Intel integration (G8)
[ ] End-to-end test on Windows host (source → action)
[ ] Single incident traceable from source to action
```
