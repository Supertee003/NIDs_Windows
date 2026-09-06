# AEGIS NIDs Windows — Canonical Architecture (G1)

**สถานะ:** เอกสารนี้คือ **Single Source of Truth** ทาง architecture (ตั้งแต่ 2026-09-06)
**ที่มา:** รวมจาก README.md (root) + PHASE32–44 READMEs (archive ไว้ที่ `docs/archive/`)
**Baseline:** ดู `docs/BASELINE_20260906.md`

---

## 1. Authority Model (ห้ามแก้)

```text
Nose (Go/C)      = sensor — observe only, no policy authority
Core (Zig)       = runtime — no direct enforcement
Brain (Python)   = advisory — cannot enforce
Shield (Rust)    = PEP — FINAL enforcement authority
Mouth (Rust)     = display only
WFP driver       = kernel enforcement, สั่งได้จาก Shield/PEP path เท่านั้น
```

ทุก module ใหม่ต้องเข้ากฎ: Detection/Correlation/Cluster ส่ง **evidence** เท่านั้น
การ block/kill/quarantine เกิดที่ WFP ผ่าน Rust PEP เท่านั้น

## 2. Pipeline

```text
Npcap capture (passive) ──────┐
Host telemetry (ETW/FIM/Reg) ─┤→ CanonicalEvent → EventPump → HostTelemetry
ML flow detector ─────────────┘        → incidents → ClusterCoord → XdrEngine (CEF→SIEM)
                                       → enforcement = WFP (Shield only)
```

## 3. Component Map — Phase 32–44 (สถานะตามจริง ตาม Rule 3)

| Phase | Component | ไฟล์ | สถานะ |
|---|---|---|---|
| 32 | Npcap capture sensor | `core/npcap_capture.zig` | REAL (field-verified, passive only) |
| 33 | SIEM forwarder | `core/siem_forwarder.zig` | PARTIAL — file transport เท่านั้น, http/tcp ⏳ |
| 35 | Backup/Recovery | `aegis_backup.ps1` / `aegis_restore.ps1` | REAL (scripts) |
| 36 | ML flow detector | `core/ml_detector.zig` | REAL inference — model ฝึกจาก **synthetic** data, ยัง**ไม่ได้ wire** เข้า pipeline |
| 37 | HIDS correlation | `core/host_telemetry.zig` | LOGIC REAL — รอ adapters ป้อน event จริง |
| 37E1 | Mock telemetry source | `core/host_telemetry_mock.zig` | MOCK — test scaffolding เท่านั้น |
| 37E2 | MITRE scenario library | `core/host_telemetry_scenarios.zig` | MOCK (test) |
| 37E3 | Extended detectors | `core/host_telemetry_detectors.zig` | REAL heuristics; injection detector **ถูกแทนด้วย Ext7** |
| 37E4 | Windows adapters (polling) | `core/windows_adapters.zig` | REAL on Windows (HOST-VERIFIED บางส่วน) — **ถูกแทนด้วย Ext5 ด้าน latency** |
| 37E5 | ETW realtime source | `core/etw_realtime.zig` | REAL on Windows, stub on Linux |
| 37E7 | T1055 injection detector | `core/injection_detector.zig` | REAL-time ETW path, ยังไม่ผ่าน Windows-host verification |
| 39 | Cluster coordination | `core/cluster_coord.zig` | LOGIC REAL — federation transport ต่องานเพิ่ม |
| 39E1 | Federation codec | `core/federation_codec.zig` | REAL (CRC32 = bit-flip detection ไม่ใช่ tamper resistance) |
| 39E2 | TCP transport | `core/federation_tcp.zig` | REAL — **plaintext** |
| 39E3 | TLS/mTLS | `core/federation_tls.zig` | **MOCK (passthrough)** — production ต้องแทนด้วย SChannel/CNG (G14) |
| 40 | Compliance reporter | `compliance_reporter.zig` | CHECK-THE-BOX — หลาย control เป็น `always_true`, ไม่ใช่ compliance assessment จริง |
| 41 | Perf benchmark | `core/perf_benchmark.zig` | REAL (source = mock event source) |
| 42 | Registry trie | `core/registry_trie.zig` | REAL, drop-in ของ RegistryWatchQueue |
| 43 | Federation bench | `core/federation_bench.zig` | REAL (loopback, in-process) |
| 44 | E2E integration test | `core/integration_test.zig` | REAL modules + **scripted mock source** |

**กติกา:** ห้ามอ้าง component เป็น "production" เกินสถานะในตารางนี้

## 4. Contradictions ที่ resolved แล้ว

1. **Kill switch wording** — ทุกที่หมายความเดียวกัน: detection ปิด default, เปิดด้วย `enabled=true` (config จริง `kill_switch.enabled=false`)
2. **Phase number collision** — "Phase 40" ปรากฏสองความหมาย (rollback ในตารางเก่า / compliance reporter ใน README จริง) → ใช้ตาม PHASE40_README.md = Compliance Reporting
3. **Superseded modules** — Ext3 injection heuristic < Ext7; Ext4 polling < Ext5 ETW (Ext4 ยังใช้ได้เป็น fallback แต่ Ext5 คือ production path)
4. **Phase 37 README tier table** — ผิดเรื่อง Phase 33/34 → ใช้ตาม README ของแต่ละ phase

## 5. Integration Gaps ที่เหลือ (ตรงกับ Gates ใน report)

- G2: Canonical Event ยังต้อง freeze ข้าม network/host/federation
- G8/G11: ETW/FIM/Reg จริงต้องพิสูจน์บน Windows host + event ID เดียวตลอด path
- G10: Rust PEP ↔ WFP kernel bridge ยัง "fallback to in-memory" (device access denied ใน test env ต้อง elevated shell)
- G12: WFP จริงยังไม่ผ่าน E2E proof
- G14: Federation TLS ยัง passthrough — ห้ามใช้ production
- ML (Phase 36) ยังไม่ wire เข้า pipeline จริง
- ระบบ compliance สองชุด (`compliance_proof.zig` G19 กับ Phase 40 reporter) ต้องรวมหรือแยกบทบาทชัด

## 6. เอกสาร archive

`PHASE*_README.md` ทั้ง 20 ไฟล์และ `ARCHITECTURE_phase20.md` ย้ายไป `docs/archive/` —
อ้างอิงเชิงประวัติศาสตร์เท่านั้น หากเนื้อหาขัดกับเอกสารนี้ **เอกสารนี้ชนะ**
