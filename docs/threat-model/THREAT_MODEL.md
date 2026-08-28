# AEGIS NIDS — Threat Model (v3.0)

## Table of Contents

1. [Overview](#overview)
2. [Attack Surface](#attack-surface)
3. [Threat Actors](#threat-actors)
4. [Threat Catalog (STRIDE)](#threat-catalog-stride)
5. [Mitigations](#mitigations)
6. [Trust Boundaries](#trust-boundaries)
7. [Data Flow Security](#data-flow-security)
8. [Residual Risks](#residual-risks)
9. [Security Testing](#security-testing)
10. [Incident Response](#incident-response)

---

## Overview

AEGIS NIDS is a Network Intrusion Detection System that monitors network traffic,
detects threats, and enforces blocking via WFP kernel driver. This threat model
identifies assets, attack surfaces, threats (using STRIDE), and mitigations.

**System Version:** v3.0 (Golden Path + Multi-Language Integration + Production Hardening)
**Test Coverage:** ~558 Zig tests across 43 test files
**Architecture:** 6-thread, 6-language (Zig/C++/Rust/Go/Python/Cython)

---

## Attack Surface

### 1. Network Input (Sensor Layer)
- **WFP callout driver** receives raw packets from kernel
- **Named pipe IPC** (`\\.\pipe\aegis_sensor_pipe`) accepts connections from Python sensors
- **UDP port 9999** (Python brain) receives suspicious payloads
- **HTTP port 9200** (Go aggregator) exposes REST API

### 2. Kernel Attack Surface
- **WFP callout driver** (`aegis_wfp.sys`) — kernel-mode code, highest privilege
- **Minifilter driver** (`aegis_minifilter.sys`) — filesystem monitoring, kernel-mode
- **IOCTL interface** — user-mode to kernel communication channel

### 3. Inter-Process Communication
- **C++ IPC bridge** (`aegis_ipc.dll`) — shared memory between Zig/Python/C++
- **NDJSON log files** — read by Go aggregator, writable by Zig pipeline
- **Blocked IPs JSON** — read/written by WFP IOCTL module

### 4. Configuration Files
- **Rules.json** — detection rules (loaded at startup)
- **Environment variables** — runtime configuration

---

## Threat Actors

| Actor | Motivation | Capability | Likelihood |
|-------|-----------|------------|------------|
| External attacker | Evade detection, disable NIDS | Network access, exploit kits | High |
| Malicious insider | Disable monitoring, exfiltrate data | Local access, admin rights | Medium |
| Malware | Persist, evade, exfiltrate | Code execution on host | High |
| Supply chain | Inject malicious code | Compromised dependencies | Low |
| Operator error | Misconfiguration | Admin access | Medium |

---

## Threat Catalog (STRIDE)

### S — Spoofing

| ID | Threat | Component | Risk |
|----|--------|-----------|------|
| S1 | Attacker impersonates sensor via named pipe | Pipe IPC | Medium |
| S2 | Forged UDP packets to Python brain (:9999) | Brain UDP | Medium |
| S3 | Unauthorized REST API access to Go aggregator | HTTP :9200 | Low |

**Mitigations:**
- S1: Named pipe uses admin-only ACL (SDDL, BP19)
- S2: Brain listens on 127.0.0.1 only (localhost)
- S3: REST API on localhost only, no auth (trusted network assumption)

### T — Tampering

| ID | Threat | Component | Risk |
|----|--------|-----------|------|
| T1 | Attacker modifies Rules.json to disable detection | Config | High |
| T2 | Attacker modifies blocked_ips.json to unblock themselves | WFP IOCTL | Medium |
| T3 | Attacker tampers NDJSON log to remove evidence | Forensics | Medium |
| T4 | Attacker modifies binary (aegis-nids.exe) | Binary | High |

**Mitigations:**
- T1: Rules.json should be read-only (file ACL), loaded at startup
- T2: blocked_ips.json is derived from in-memory table (re-synced on write)
- T3: NDJSON is append-only with rotation (logs/aegis_core.N.ndjson)
- T4: Binary should be signed (future: code signing)

### R — Repudiation

| ID | Threat | Component | Risk |
|----|--------|-----------|------|
| R1 | Attacker denies actions because logs were deleted | Forensics | Medium |
| R2 | Blocked IP claims they weren't blocked (no audit trail) | WFP | Low |

**Mitigations:**
- R1: NDJSON logs use append-only mode + rotation (7 files, 100MB each)
- R2: Blocked IPs persisted to blocked_ips.json (IR-02) + forensic log

### I — Information Disclosure

| ID | Threat | Component | Risk |
|----|--------|-----------|------|
| I1 | Attacker reads NDJSON log (contains src IPs, payloads) | Forensics | High |
| I2 | REST API exposes alert details (src IPs, rules) | Go API | Medium |
| I3 | Named pipe payload visible to other processes | Pipe IPC | Medium |
| I4 | Memory dump exposes threat intel DB | RAG | Low |

**Mitigations:**
- I1: Log files should have restricted ACL (admin-only access)
- I2: REST API on localhost only (trusted network)
- I3: Named pipe uses admin-only ACL (BP19)
- I4: RAG DB is in-memory only (not persisted to disk)

### D — Denial of Service

| ID | Threat | Component | Risk |
|----|--------|-----------|------|
| D1 | Attacker floods named pipe with events (queue overflow) | Fabric | High |
| D2 | Attacker floods UDP brain port with garbage | Brain | Medium |
| D3 | Attacker floods REST API with queries | Go API | Low |
| D4 | Attacker exhausts memory by sending many unique flows | FlowTable | Medium |

**Mitigations:**
- D1: Pressure-aware sampling (STEP 4) drops low-priority at source
- D2: Brain has MAX_PAYLOAD_SIZE (4096 bytes) + UDP recv timeout
- D3: Go aggregator has MAX_ALERTS (10000) cap with dedup
- D4: FlowTable is bounded (4096 max flows, 60s timeout, STEP 5)

### E — Elevation of Privilege

| ID | Threat | Component | Risk |
|----|--------|-----------|------|
| E1 | WFP driver IOCTL allows unprivileged user to block arbitrary IPs | WFP IOCTL | High |
| E2 | Buffer overflow in C++ packet parser leads to code execution | C++ Bridge | Critical |
| E3 | Integer overflow in wire decoding leads to memory corruption | Wire Codec | High |
| E4 | Race condition in FlowTable allows data corruption | Flow Engine | Medium |

**Mitigations:**
- E1: WFP device handle requires admin privileges to open (BP19 ACL)
- E2: C++ parser uses bounds-checked parsing (STEP 17, ParseStatus validation)
- E3: Wire codec uses explicit field-by-field encoding (STEP 2B, no memcpy)
- E4: FlowTable uses mutex (STEP 5, std.Thread.Mutex per operation)

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    KERNEL MODE                              │
│  ┌─────────────────┐  ┌──────────────────┐                │
│  │ WFP Callout     │  │ Minifilter       │                │
│  │ Driver (.sys)   │  │ Driver (.sys)    │                │
│  └────────┬────────┘  └────────┬─────────┘                │
│           │ IOCTL              │ FLT_COMM                  │
├───────────┼────────────────────┼───────────────────────────┤
│           │   USER MODE        │                           │
│  ┌────────▼──────────────────▼────────┐                   │
│  │     Zig Core Pipeline (aegis-nids)  │                   │
│  │  ┌─────────────────────────────┐    │                   │
│  │  │ Event Fabric (ring buffer)   │    │                   │
│  │  │ Nose Integration (sampling)  │    │                   │
│  │  │ Flow Engine (FlowTable)     │    │                   │
│  │  │ Detection (escalation)      │    │                   │
│  │  │ Correlation (XDR incidents) │    │                   │
│  │  │ RAG (threat intel DB)       │    │                   │
│  │  │ Policy (rules + PEP)        │    │                   │
│  │  │ Forensics (ring + NDJSON)   │    │                   │
│  │  └─────────────────────────────┘    │                   │
│  └──┬──────┬──────┬──────┬──────┬──────┘                  │
│     │ FFI  │ FFI  │ IPC  │ UDP  │ NDJSON                  │
│  ┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──────┐                │
│  │ C++  ││Rust ││Python││Brain││Go Aggr  │                │
│  │Bridge││Shield││Brain ││(UDP)││(HTTP)   │                │
│  └─────┘└─────┘└─────┘└─────┘└─────────┘                 │
│     │                                                    │
│     │ Named Pipe (\\.\pipe\aegis_sensor_pipe)             │
│  ┌──▼──────────┐                                         │
│  │ External     │   ← TRUST BOUNDARY (network)            │
│  │ Python       │                                         │
│  │ Sensors      │                                         │
│  └─────────────┘                                         │
└─────────────────────────────────────────────────────────────┘
```

**Trust levels:**
1. **Kernel mode** — highest trust (driver code)
2. **Zig core** — trusted (compiled, no external input parsing)
3. **FFI modules** (C++/Rust/Cython) — trusted (compiled, called via FFI)
4. **IPC services** (Python/Go) — trusted (localhost only, but separate process)
5. **External sensors** — untrusted (network input, must validate)

---

## Data Flow Security

### Network Packet → Detection Pipeline
1. WFP callout captures packet (kernel mode)
2. IOCTL transfers to user-mode (IOCTL_AEGIS_READ_EVENTS)
3. C++ PacketParser validates headers (bounds-checked, STEP 17)
4. Zig pipeline processes (validate magic/version before reading fields)
5. Forensics logs (append-only NDJSON)

**Security:** Input validation at every boundary (STEP 1 canonical event validation, STEP 2B wire format CRC32, STEP 17 C++ bounds-checked parsing)

### Sensor → Named Pipe → Pipeline
1. External Python sensor connects to `\\.\pipe\aegis_sensor_pipe`
2. Admin-only ACL (SDDL, BP19) — non-admin connections rejected
3. Payload received via ReadFile (max 4096 bytes)
4. Event created via `nose_int.submit()` (validates magic/version)
5. Pressure-aware sampling may drop (STEP 4)

**Security:** ACL + validation + pressure sampling

### Pipeline → WFP Block
1. Policy decides BLOCK (PolicyEngine.evaluate)
2. PEP calls `wfp_ioctl.block_ip(source_ip)`
3. IOCTL_AEGIS_BLOCK_FLOW sent to kernel driver
4. Kernel adds FWP_ACTION_BLOCK at FWPM_LAYER_INBOUND_TRANSPORT_V4
5. Blocked IP persisted to `logs/blocked_ips.json` (IR-02)

**Security:** Admin-only device handle + IOCTL validation + persistence for IR

---

## Mitigations Summary

| Category | Mitigation | Step | Status |
|----------|-----------|------|--------|
| Wire format | Explicit field-by-field encoding (no memcpy) | 2B | ✅ |
| ABI safety | i128→u64, validate magic+version+size | 1 | ✅ |
| Backpressure | Pressure-aware sampling + backoff | 4 | ✅ |
| Flow tracking | Bounded FlowTable (4096 max, 60s timeout) | 5 | ✅ |
| Detection | Flow-aware escalation + risk score | 6 | ✅ |
| Correlation | Session-based XDR linking + incident TTL | 7,14 | ✅ |
| Threat intel | RAG enrichment (severity escalation + risk delta) | 8 | ✅ |
| Enforcement | PEP calls WFP IOCTL (actual kernel block) | 9,23 | ✅ |
| Forensics | Ring buffer (4096) + NDJSON (append-only, rotation) | 10 | ✅ |
| C++ parsing | Bounds-checked, zero-copy, ParseStatus validation | 17 | ✅ |
| Rust scoring | Severity * confidence scoring + threshold | 18 | ✅ |
| Go dedup | SHA-256 hash dedup + MAX_ALERTS cap | 19 | ✅ |
| Python brain | DEFCON escalation + UDP localhost only | 20 | ✅ |
| Cython | Pattern matching + 10 default patterns | 21 | ✅ |
| Metrics | Prometheus export (aegis_* naming) | 22 | ✅ |
| Stress | 1000+ events, 4-thread concurrent, ring overflow | 24 | ✅ |
| Memory | Zig testing allocator leak detection | 25 | ✅ |
| Crash recovery | Graceful shutdown + state cleanup | 26 | ✅ |

---

## Residual Risks

| Risk | Description | Mitigation Status | Future Work |
|------|-------------|-------------------|-------------|
| Unsigned binary | Attacker can replace aegis-nids.exe | None | Code signing (future) |
| No TLS on REST API | Go aggregator HTTP unencrypted | Localhost only | Add TLS for remote deploy |
| No auth on REST API | Anyone on localhost can query | Localhost only | Add API key/token |
| WFP driver unsigned | Driver can be tampered | None | Driver signing (WHQL) |
| NDJSON unencrypted | Log files readable by admin | File ACL | Encrypt at rest (future) |
| Stub vs production FFI | Stubs may diverge from real | Kept in sync | DynLib loading (future) |
| Single-thread forensics | Ring mutex may bottleneck | 4096 entries (fast) | Sharded ring (future) |

---

## Security Testing

### Test Coverage
- **~558 Zig tests** across 43 test files
- **10 IPS canary tests** (STEP 13) — BLOCK scenario verification
- **10 stress tests** (STEP 24) — 1000+ events, multi-thread
- **10 memory leak tests** (STEP 25) — allocator tracking
- **12 crash recovery tests** (STEP 26) — graceful shutdown

### Security Test Categories
1. **Validation tests** — wrong magic/version/CRC rejected (STEP 1, 2B)
2. **Overflow tests** — queue overflow, ring overflow (STEP 24)
3. **Edge case tests** — 0/max IPs, empty payload, short buffer (STEP 13, 23)
4. **Multi-thread tests** — concurrent submission safety (STEP 11, 24)
5. **Graceful degradation** — device not open → .failed (STEP 13, 23)
6. **Memory safety** — no leaks across 5 init/shutdown cycles (STEP 25)

---

## Incident Response

### Detection
- Forensic log (`logs/aegis_core.ndjson`) — PIPELINE_BLOCK, DETECTION_BLOCK, XDR_CORRELATION
- Go aggregator REST API — `GET /api/alerts/critical`
- Blocked IPs file — `logs/blocked_ips.json`
- Metrics — `aegis_policy_blocks_total`, `aegis_fabric_dropped_total`

### Response Procedure
1. Check Go aggregator for critical alerts: `curl http://127.0.0.1:9200/api/alerts/critical`
2. Review forensic log for BLOCK events: `Select-String aegis_core.ndjson -Pattern "BLOCK"`
3. Check blocked IPs: `Get-Content logs\blocked_ips.json`
4. If false positive: unblock IP: `.\scripts\aegis_unblock.py <ip>`
5. If under attack: verify DEFCON level (Python brain)
6. If overwhelmed: increase queue capacity or add detection threads

### Forensics Replay
```powershell
# Query by session_id (incident investigation)
# Via Zig pipeline (in-memory ring):
# forensics_int.query(.{ .session_id = 42 })

# Via NDJSON log (persistent):
Select-String aegis_core.ndjson -Pattern "session_id.*42"
```

### Post-Incident
1. Preserve forensic logs (copy to secure location)
2. Review metrics for attack timeline
3. Update Rules.json with new detection patterns
4. Rebuild + redeploy with updated rules
5. Run health check: `.\health_check.ps1`
