# AEGIS Sprint 2 Plan (Phase 32+)

## Sprint 2 Goal: NIDS → HIDS + IPS + XDR Foundation

Blueprint กำหนดเส้นทาง:
```
NIDS (✅ complete in Sprint 1)
  ↓
HIDS (host sensors: process, registry, file integrity)
  ↓
Detection Platform (multi-vector correlation)
  ↓
IPS (inline blocking via PEP)
  ↓
XDR (cross-tier correlation + RAG intelligence)
```

## Sprint 2 Tasks

### AEGIS-009: HIDS Process Monitor (Phase 32)
- Create `core/hids_process_monitor.zig`
- Monitor process creation/exit via WMI or ETW
- Submit host events via Nose Contract (EventSource.host_sensor)
- Detect suspicious process names, parent-child anomalies

### AEGIS-010: HIDS File Integrity Monitor (Phase 32)
- Create `core/hids_file_monitor.zig`
- Watch critical system files (System32, startup, hosts file)
- Hash-based integrity checking
- Submit file change events via Nose Contract

### AEGIS-011: IPS Inline Blocking Mode (Phase 33)
- Wire PEP to actually call `wfp_ioctl.block_ip()` (currently sets status only)
- Add `enforce_block` that calls WFP kernel filter
- Track enforcement latency for monitoring

### AEGIS-012: Flow Engine (Phase 33)
- Create `core/flow_engine.zig`
- Track FlowKey (src_ip, dst_ip, src_port, dst_port, protocol)
- FlowState (packet_count, byte_count, tcp_state, risk_score)
- Required for IPS (stateful blocking decisions)

### AEGIS-013: XDR Correlation Engine (Phase 34)
- Enhance Go aggregator with cross-tier correlation
- Link network events (WFP) with host events (HIDS) via session_id
- Timeline reconstruction for IR analysts

### AEGIS-014: RAG Intelligence Layer (Phase 34, optional)
- Python brain receives events + queries threat intelligence DB
- Enrich CanonicalEvent with context_flags
- RAG must NOT override deterministic policy

### AEGIS-015: TypeScript Policy Plane (Phase 35, optional)
- Policy IR (intermediate representation)
- Rule compiler from YAML → policy rules
- Simulator for testing policy changes

## Sprint 2 Principles (from Blueprint)

1. **Sensors ≠ Detection** — HIDS sensors only capture, don't detect
2. **Policy ≠ Enforcement** — IPS policy sets action, PEP executes
3. **RAG ≠ Source of Truth** — RAG enriches, doesn't decide
4. **All via Canonical Event** — No direct cross-module calls
5. **Versioned Contracts** — All schemas versioned (magic + version)

## Sprint 2 Success Criteria

Blueprint กำหนดว่าสำเร็จเมื่อตอบได้ครบ:
```
Event นี้มาจากไหน? → EventSource enum
ถูก normalize ที่ไหน? → nose_contract.createEvent()
schema version อะไร? → CanonicalEvent.version
เข้า queue ไหน? → PriorityQueue (HIGH/NORMAL/LOW)
priority เท่าไร? → Priority.fromEvent()
detector ไหนตรวจ? → DetectionManager.detect()
evidence คืออะไร? → DetectionResult
correlation กับ event ไหน? → Go Aggregator Correlator
brain เพิ่ม context อะไร? → PolicyContext
policy version ไหนตัดสิน? → PolicyEngine.evaluate()
PEP ทำ action อะไร? → PEP.enforce()
ผล action ถูกบันทึกที่ไหน? → forensic_log (NDJSON)
สามารถ replay เหตุการณ์นี้ได้หรือไม่? → Go Aggregator timeline
```
