# AEGIS NIDS — Development Plan Report (Start → Finish)

**Generated:** 2026-10-05 · **HEAD:** `5c21014` · **Truth:** TRUTH_VALID (working tree) · **Release:** 529/529 match
**Scope:** ซ่อม/ต่อ backend ให้ครบเส้นเดียว (single production spine) + ล็อกสัญญาข้ามภาษา + ปิดช่อง observe-only ที่พูดเกินจริง
**Method:** vertical slice / patch transaction (AGENTS.md) — 1 flow contract ต่อ 1 patch, มี test pin ทุก patch, ห้ามเคลมเกินหลักฐาน (E0–E7)
**User constraint (ถาวร):** ห้ามลบมั่ว — เปลี่ยนแบบ additive เสริมการทำงานก่อนเสมอ; จะลบได้เฉพาะของที่พิสูจน์แล้วว่า quarantined + zero importers + มี pin กัน + กู้คืนได้จาก git (เช่น DISP-MIGRATE-047)
**บทเรียน DISP-MIGRATE:** ลบ dispatcher 2 ไฟล์ตามเงื่อนไขครบ แต่ subsystems ที่มัน orchestrate (Universe-B: verdict/threat-intel/rag/brain/policy facades) ยังอยู่และอาจ integrate วันหน้า — จึง restore กลับเป็น quarantined reference (`2a38b94`) pins ยังชี้ production files เหมือนเดิม

---

## 1. Baseline ที่เริ่ม (ก่อน session นี้)

- Production spine เดียว: `nose (Go)` → named pipe → `aegis_nids.exe (Zig)` → `aegis_pep.dll (Rust)` → forensic ring → SIEM/brain (opt-in) → control pipe
- Authority: Rust PEP เจ้าเดียว, control = named pipe เท่านั้น, detection ≠ host-effect
- งาน T-series ก่อนหน้า (SIEM, brain loop, two-person, IPv6 wire, TS-IR, canary, stub handlers) ลงแล้วถึง `ca419a2`

## 2. Slices ที่ลงแล้วใน session นี้ (ตามลำดับ commit)

| # | PATCH-ID | เนื้อหา | HEAD |
|---|---|---|---|
| 1 | B3-SIM-029 | `enforcement.simulate` canned-allow → posture projection (ไม่แตะ PEP) + CLI `enforce simulate` | `5f6b417` |
| 2 | NET-LOOPBACK-030 | metrics exporter `0.0.0.0` → `127.0.0.1` + refuse non-loopback `--host` | `5cf9f6b` |
| 3 | GO-LOOPBACK-031 | aggregator REST `:9200` → `127.0.0.1:port` (`apiAddr` pin + Go test) | `dc72865` |
| 4 | VER-TRUTH-032 | version ที่ CLI+daemon รายงานขัด source (nose/pep/brain/aggregator) + cross-check pin | `2180c49` |
| 5 | SIEM-CFG-033 | `siem_config.json` note "not implemented" ค้าง (forwarder ครบ 5 transports) + contract pin + mutation-proof | `ecf97fb` |
| 6 | B2-HOTRL-034 | Tier-2 hot-reload: ไฟล์ torn/missing/invalid เก็บ engine เดิม (`maybe_reload_rules`) | `412723c` |
| 7 | ANOM-COUNT-035 | `anomalies_emitted` มีชีวิตใน `observe()`; ลบ `g_pipeline_anomalies` (write-only) | `1f6471e` |
| 8 | V6-FLOW-036 | v2 sidecars รอด queue ถึง flow key (`pushDecodedFrame`, `is_ipv6`, u32 identity ไม่แตะ) | `bde1c2c` |
| 9 | V6-DETECT-037 | anomaly baseline ตาม sidecars (`entityKeyBytes`, fallback byte-identical) | `3bd965c` |
| 10 | BLOCK-LABEL-038 | `block/quarantine list` ติดป้าย local-candidates (ไม่ให้อ่านเป็น live block) | `b424387` |
| 11 | VER-NS-039 | 5-vs-1 คือคนละ namespace (wire AEG1 vs internal IPC-96) + disjointness pin | `19c9423` |
| 12 | CTL-DOC-040 | control doc ต่อ section v2 (33 commands+roles, retired names) + parity pin | `4415d4e` |
| 13 | B2-LOGTH-041 | throttle `anomalous.json` (100/60s + DROPPED_COUNT, ไม่ rotate เพราะ mouth tail reader) | `f8c5211` |
| 14 | NOSE-DISC-042 | corrupt length ไม่ stall reader (drain ≤64KB, เกินนั้น drop connection resync) | `4595e9a` |
| 15 | PIPE-SUB-043 | pipe marker prefix → substring (prefix hits เดิมไม่หาย) | `2a5c73d` |
| 16 | FIM-LONGPATH-044 | native FIM: strict UTF-8 + `\\?\` extended paths + ปิด leak | `bca337e` |
| 17 | REG-STUB-045 | ติดป้าย `windows_adapters.zig` เป็น demo-only + pin ห้าม prod import | `5c21014` |

ทุก patch: `zig build` + `zig build test` + `go test` + `cargo test` + pytest ที่เกี่ยว + `truth.py verify` + `release_engineering --verify` เขียวคู่ก่อน commit (flake ที่ไม่ใช่ของ slice ถูกบันทึก ไม่ถูกซ่อน)

## 3. งานค้างใน working tree (ยังไม่ commit — สถานะตามจริง)

| งาน | ไฟล์ | สถานะ |
|---|---|---|
| ETW-STR-046 | `src/windows/etw_native.c` (M), `tests/security/test_etw_session_name.py` (??) | code+test เสร็จ, **ยังไม่รัน gates** (mingw compile ETW ไม่ได้ — ต้อง MSVC; pin เป็น E1 static) |
| DISP-MIGRATE (partial) | `src/policy/dispatcher*.zig` (D), `tests/e2e/test_t14…`, `tests/forensics/test_t12…` (M) | **แดง 1 test**: `test_event_processor_is_sole_orchestrator` คาด `processFlow` ฯลฯ แต่ `event_processor.zig` รวม stages แบบ inline (มีแค่ `processEvent` + `pipelineLoop`) — ต้องแก้ test ให้ตรวจ inline stages แทน แล้วค่อย commit |

## 4. แผนจบงาน (ตามลำดับ)

### Phase A — ปิดงานค้าง (doing now)
1. **A1. ซ่อม T14 test** → ตรวจ inline stage keywords ใน `processEvent` → `pytest T14+T12` เขียว
2. **A2. Commit DISP-MIGRATE** (ลบ dispatcher 2 ไฟล์ + T14/T12 pins ใหม่) → rebump + gates
3. **A3. Commit ETW-STR-046** (pin E1 static; บันทึกข้อจำกัด mingw/MSVC) → rebump + gates

### Phase B — ตัดสินใจที่ค้าง (ต้อง owner verdict — ถามทีละข้อ ไม่เดา)
4. **B1. Canary drift 2 จุด** (`rfi_basic` High-vs-Critical, `data_exfil` Low-vs-High): runner รายงานถูกแล้ว — ต้องการคำตอบว่า file หรือ definition ถูก
5. **B2. Mouth version drift** (Cargo 3.0.0 vs binary `--version` 1.0.0): bump string หรือ document
6. **B3. FED-XDR**: permanent test-only หรือ Project 4+ cluster
7. **B4. Dispatcher deletion final**: หลัง A2 — ยืนยัน zero prod importers แล้วลบ (T14/T12 pins ใหม่กันไว้)

### Phase C — T7 seal (ปลดล็อก enforcement path)
8. **C1. `PepContext.policy_version`** (ปัจจุบัน 0, Rust ไม่ใช้): ต่อ verified IR version เมื่อมี loader ที่ verify ลายเซ็น
9. **C2. `signed_by` validation + receipt reconciliation**: จาก cosmetic → enforced
10. **C3. trust_store (CNG) + two-person API + policy_signing**: Ed25519 verify → trust → enforce (ปัจจุบัน `requiresTrustedAuthorization` บังคับ non-enforcing ถูกต้องแล้ว)

### Phase D — v6 เต็มเส้น + robustness ที่เหลือ
11. **D1. Forensic v6**: record 4096B เป็น ABI แช่แข็ง — ต้อง design bump strategy (ไม่ ad-hoc)
12. **D2. Brain 4096 truncation**: evasion-by-padding หรือ bound ที่ยอมรับได้ — ต้องการ verdict (chunked scan vs document)
13. **D3. RAG overmatch / brain UDP spoofable / receipt reconciliation / watchdog toothless**: ทีละ slice พร้อมหลักฐาน

### Phase E — สิ่งแวดล้อม (นอก repo — ต้อง elevated shell)
14. **E1. Restart daemon** (PID เก่าเป็น binary ก่อน patch หลายรุ่น): `stop --all` (privileged) แล้วรัน binary ใหม่ → ปลด live-proof ที่ skip ไว้ (`test_enforce_simulate` live-shape)
15. **E2. ลบ dead `pytest-current` symlink** ใน Temp (admin-owned): ไม่งั้น `tmp_path` teardown ระเบิดทุกไฟล์บน host นี้ (lab tests เก่าโดนอยู่แล้ว)

## 5. Completion gates (ก่อนปิดแต่ละ Phase)

- `zig build` / `zig build test` / `go test ./...` / `cargo test` / pytest subset / `truth.py verify` / `release_engineering --verify` (529 artifacts)
- ห้ามเคลม E-level เกินหลักฐาน · stale-daemon/skip ต้องมีเหตุผลบันทึก · docs ที่ frozen (v1) แตะด้วย append-only

## 6. ความเสี่ยงที่รู้ตัว

- Daemon เก่า (E1) ทำให้ live-shape tests เป็น skip — ไม่ใช่ code ผิด แต่ต้อง restart ก่อนอ้าง E4
- mingw compile C helpers บางไฟล์ไม่ได้ (ETW) — canonical คือ MSVC; pin ระดับ E1 + บันทึกไว้
- `dispatcher` ลบแล้วแต่ pins เก่าอ้างชื่อไฟล์ — A1/A2 ปิดประเด็นนี้
- Temp symlink (E2) เป็น host-state — ไม่ใช่ repo bug, แก้ด้วย elevated shell เท่านั้น
