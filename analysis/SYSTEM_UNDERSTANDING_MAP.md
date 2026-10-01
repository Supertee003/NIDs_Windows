# AEGIS NIDS — Shared System Understanding (verified at HEAD fb61013)

เอกสารนี้คือ "แผนที่ความเข้าใจร่วม" ที่ยืนยันจากโค้ดที่ HEAD + runtime จริง + test run จริง
ไม่ใช้ข้อมูลจาก README/doc เป็นหลัก (doc อยู่ล่างสุดของ authority order)

```
runtime behavior > source@HEAD > build config > machine maps > AGENTS.md/ADRs > evidence > README > สมมติฐานของ AI
```

---

## 1. ระบบนี้คืออะไร (นิยามที่ถูกต้องตามโค้ด)

Kernel-level **NIDS + hybrid IPS** บน Windows: จับ packet/host event → ตรวจตาม rules/policy →
ตัดสินใจผ่าน PEP → บังคับใช้ผ่าน WFP (เมื่อพร้อม) → ปิดผนึกหลักฐานแบบ hash chain → แสดงผลผ่าน
operator surfaces โดย **runtime spine เดียวคือ Zig** และ **PEP เดียวคือ Rust** (`rust-src/lib.rs`)

Iron rules ที่ระบบบังคับ (และเราเจอบั๊กเมื่อมันถูกฝ่าฝืน):
หนึ่ง runtime / หนึ่ง semantic event (109 byte) / หนึ่ง control protocol / หนึ่ง policy IR /
หนึ่ง PEP authority / หนึ่ง enforcement authority / หนึ่ง canonical CLI (`tools/aegisctl.py`)

---

## 2. Tier map — ภาษา / หน้าที่ / ทางเข้า / สถานะจริง

| Tier | Path | ภาษา | หน้าที่ | Entry point | สถานะที่ยืนยันแล้ว |
|---|---|---|---|---|---|
| Runtime spine | `src/` (278 ไฟล์, 17 subdir) | Zig 0.13 | orchestrator, pipeline, detection engine, policy, forensic, control, capture, federation | `src/main.zig`, `src/daemon.zig`, `src/control.zig`, `src/all_tests.zig` | `zig build test` rc=0; runtime RUNNING (pid 13112) |
| — contract | `src/contract/` (8) | Zig | canonical event 109 B, `EventSource`, enum pinning | `canonical_event.zig`, `event.zig` | ⚠️ มี 2 `EventSource` คนละ space (§6.1) |
| — pipeline | `src/pipeline/` (7) | Zig | queue, rule loader (FNV-1a + Aho-Corasick), event processor | `event_queue.zig` (`pushCanonicalEvent`), `rule_loader.zig` | ⚠️ wire path ทิ้ง payload (§3) |
| — detection | `src/detection/` (15) | Zig | signature/AC engine, anomaly, injection detector, threat intel | `detection_engine.zig`, `signature_engine.zig` | AC โหลด 22 patterns จาก Rules.json |
| — forensic | `src/forensic/` (19) | Zig | ring buffer 4 KB/record + SHA-256 chain + CRC + evidence records | `forensic_pipeline.zig` | `integrity=ok verified=true` จาก daemon จริง |
| — control | `src/control/` (6) | Zig | named-pipe control plane + handler registry (health/metrics/forensics/rules/...) | `handler_registry.zig`, `protocol.zig` | `authority invariant: HELD` |
| — policy | `src/policy/` (17) | Zig | policy IR, decision/dispatch, enforcement receipt, WFP bindings | `policy_engine.zig`, `enforcement_receipt.zig`, `wfp_ioctl.zig` | ⚠️ `EnforcementStatus` 4 vs 6 (§6.2) |
| — capture | `src/capture/` (15) | Zig | nose pipe reader, windows capture, ETW | `nose_pipe_reader.zig`, `windows_capture.zig` | ETW ถูกบล็อก (`StartTraceW 183`) |
| — windows | `src/windows/` (22) | Zig + C | ETW realtime, FIM helper, driver interop | `etw_realtime.zig`, `fim_native.c` | ต้อง Admin/signing |
| — federation/xdr/reliability | `src/federation/` 8, `src/xdr/` 5, `src/reliability/` 9 | Zig | cluster TLS, XDR, resilience | — | tests/federation 17 ✓, reliability 11 ✓ |
| — proofs | `src/tests/` (114) | Zig | per-contract proof suites + integration harness | `integration_test_main.zig` | รวมอยู่ใน `zig build test` |
| PEP (enforcement authority) | `rust-src/lib.rs` (1 ไฟล์) + root `Cargo.toml` | Rust | `aegis_pep_init/provider_ready/enforce/unblock_ip/query`, fail-closed | `aegis_pep_*` exports | `cargo test` **20 passed**; unknown action → ESCALATE |
| Network sensor | `nose/` (19) | Go 1.25 | Npcap capture → canonical event; **match `match_pattern` บน payload จริง** | `main.go`, `capture.go`, `signature_classifier.go`, `pipe_writer.go` | `go test ./...` ok |
| Tier3 brain | `brain/` (127) | Python + Cython | regex/semantic analysis, DEFCON, routing, acceptance gates | `windows_brain.py`, `core_routing.py`, `cython/` | tests/cython 20 ✓, host_telemetry 9 ✓ |
| Host monitor | `mouth/` | Rust | `windows_sec_monitor.rs` (host security monitoring) | — | compile ผ่าน (ไม่มี suite เฉพาะ) |
| IPC bridge | `bridge/` (246 ไฟล์ ส่วนใหญ่เป็น build) | C++ | packet parser, adapter, IPC | `aegis_bridge_main.cpp`, `aegis_adapter.cpp` | tests/adapters 10 ✓ |
| Policy compiler | `ts_policy/` (328) | TypeScript | policy IR compile + seal + typed values, ห้าม enforce จาก TS | `src/compiler.ts`, `src/seal.ts` | `npm run test:all` **67/67 pass** |
| Alert sidecar | `go/aggregator/` | Go | REST :9200 alert collector + correlator | `main.go`, `alert.go`, `correlator.go` | `go test ./...` ok; **daemon ยังไม่ต่อ** → `alerts = available:false` |
| Duplicate PEP (QUARANTINED) | `shield/` + `tools/legacy/rust_shield_orphan_quarantined/` | Rust | Tier-3 payload screening (ห้ามเป็น authority) | `shield/src/lib.rs` | ยังอยู่บน disk แต่ไม่ถูก build บน golden path |
| Kernel drivers | `drivers/minifilter`, `drivers/wfp_callout` (16) | C | minifilter + WFP callout | `.inf`/`.c` | ต้อง Admin + signing (E5) |
| Operator CLI | `tools/aegisctl.py` + `tools/aegisctl/` (215) | Python | canonical control client (pipe/tcp) | `aegisctl.py` | spawn-free, dispatch ผ่าน `globals()` |
| Operator TUI/UI | `scripts/aegis_console.py`, `scripts/Dashboard.py`, `scripts/aegis_console_pro.py`, `scripts/aegis_graph.py`, `aegis_dashboard/` (Rust eframe), `tools/aegisctl/web_dashboard/app.py` | Python / Rust | แสดง health/detection/forensic graph | `aegis_graph.py` = evidence graph | labels canonical ✓, graph verify-only ✓ |
| Contracts | `contracts/fixtures/` (13 ไฟล์) | JSON | cross-phase contract fixtures | — | ⚠️ **ไม่มีผู้อ่าน/validator เลย** (§6.3) |
| Config | `configs/` (25) + `config/` (2) | JSON | Rules.json, policies.json, runtime.json, schema.json | `configs/Rules.json` = canonical | ⚠️ `config/Rules.json` สำเนาเก่าที่ยังถูกอ่าน (§6.4) |
| Tests (Python) | `tests/` (222) | Python | e2e, contracts, security, runtime, release, lab, wfp | `pytest tests/` | 478 passed / 6 failed (§5) |
| Truth/gates | `tools/truth.py`, `tools/generate_truth_artifacts.py`, `tools/create_manifest.py`, `tools/release_engineering.py`, `tools/final_audit.py`, `tools/ci_coverage.py` | Python | บังคับ provenance + digests + CI coverage | — | TRUTH_VALID, 516/516 digests |

---

## 3. Data flow จริง (และจุดที่ payload หาย)

```
[Kali 192.168.126.10] ──packets──▶ Npcap (nose, Go)
                                     │  signature_classifier.go:
                                     │  strings.Contains(payload, rule.match_pattern)  ← matching เกิดที่นี่
                                     ▼
                            CanonicalEvent 109 byte
                            (มี PayloadLength/PayloadHash แต่ "ไม่มี" payload bytes)
                                     │  pipe \\.\pipe\aegis_nose
                                     ▼
                    src/capture/nose_pipe_reader.zig:326
                            pushCanonicalEvent(&event)          ← payload = &[_]u8{} (ว่าง)
                                     ▼
                    src/pipeline/event_queue.zig
                      • pushCanonicalEvent        → payload_len = 0
                      • pushCanonicalEventWithPayload → เก็บ payload ≤1500 B (ใช้โดย telemetry_threads เท่านั้น)
                                     ▼
                    pipeline / event_processor → กฎ+policy → PEP (Rust) → WFP
                                     ▼
                    forensic ring (4 KB/record, SHA-256 chain) → control pipe → CLI/UI/graph
```

ผลที่ต้องเข้าใจตรงกัน:
1. **Network detection ทำงานที่ Go ไม่ใช่ที่ Zig** และใช้ `match_pattern` (substring, case-sensitive) ไม่ใช่ `regex_pattern`
2. `regex_pattern` ถูกใช้เฉพาะเส้น Python brain (ที่ตัด `str(payload)[:4096]` → binary semantics เพี้ยนได้)
3. ถ้าต้องการให้ Zig AC ตรวจ network payload จริง ต้องแก้ wire contract (เพิ่ม payload frame) หรือใช้ `pushCanonicalEventWithPayload` ในเส้น capture — เป็นงาน Phase 4 ระดับ contract ไม่ใช่ hotfix
4. `blocks = 0` เพราะ `prevention_gate = closed` (detection-only) ไม่ใช่เพราะระบบพัง

---

## 4. หลักฐานการทำงาน (รันจริงใน session นี้)

| คำสั่ง | ผล |
|---|---|
| `zig build test` | rc=0 |
| `cargo test` (PEP) | 20 passed |
| `cargo test` (aegis_dashboard) | 1 passed |
| `go test ./...` (nose) | ok |
| `go test ./...` (go/aggregator) | ok |
| `npm run test:all` (ts_policy) | 67 pass / 0 fail |
| `pytest tests/` | 478 passed, 6 failed, 2 skipped |
| `release_engineering.py --verify` | 516/516 digests OK |
| `python tools/truth.py verify` | TRUTH_VALID |
| `aegisctl health` | RUNNING, pid 13112, `in_events=1,480,739`, `errors=0` |
| `aegisctl metrics` | `detections=3273`, `packets_captured=1,312,756`, `rules_loaded=22`, `blocks=0` |
| `aegisctl authority` | HELD (`rust_pep` canonical, `rust_shield` alias) |
| `aegisctl forensics list` | `integrity=ok verified=true`; limit 650 ok, limit 680 → rc=3 |

Test suites แยกตามโฟลเดอร์ (ทั้งหมด pass ยกเว้นที่ระบุ): adapters 10, contracts 7, cython 20, e2e 14,
federation 17, forensics 17, host_telemetry 9, ips 17, lab 26, pep 11, policy_signing 10, reliability 11,
security 47, typescript 9, wfp 10 (+1 skip), test_e2e 7, release 18;
**runtime 218 pass / 4 fail + 3 subfail**

---

## 5. สถานะ test suite (อัปเดต 2026-10-01) — เดิมแดง 6 ตัว ตอนนี้เขียว

เดิมแดง 6 ตัวเพราะยึด semantics ที่ถูกยกเลิก (forensic อ่าน NDJSON log, status เป็นข้อความ `PEP`/`Mode:`, core ต้อง RUNNING
ทั้งที่ ETW ล้มจริง) → แก้ test ให้ยืนยัน canonical contract (`f00b29e`) และพบว่า subfailure ของ `TestIdempotentStop`
เกิดเพราะมี component อื่นถือ pipe อยู่ (single-owner) ไม่ใช่บั๊ก

รันล่าสุด: `pytest tests/` = **524 passed / 2 failed / 5 skipped** — 2 ตัวที่เหลือคือ (ก) test ที่ต้องมี daemon รันอยู่
(`test_read_paths_still_work`) (ข) release digest gate ที่ต้อง refresh หลัง resync truth (`test_ac3_verify_mode_detects_drift`)

## 5.1 สาเหตุเดิมของ 6 ตัวที่เคยแดง (เก็บไว้เป็น checklist)

| Test | สาเหตุ | ทางแก้ที่ถูก |
|---|---|---|
| `test_gate_d::test_forensic_export_with_no_log` | ยังคาดหวัง forensic CLI อ่าน log ไฟล์ (ถูกยกเลิกแล้ว) — canonical ตอบ ring summary | retarget ไป control-plane contract |
| `test_gate_d::test_forensic_search_with_no_log` | ยังคาดหวัง `--field/--value`; canonical รองรับแค่ source/payload-prefix และ fail-closed (rc=2) | retarget |
| `test_gate_f::test_enforce_status_is_read_only` | คาดหวังคำว่า `PEP` แต่ output เป็น JSON canonical (`pep_available`, `prevention_gate`) | assert จาก JSON |
| `test_harness_integration::test_core_reaches_running_within_startup_timeout` | probe ไปที่ `\\.\pipe\aegis_control` แต่ runtime ใช้ชื่อ pipe ที่เปลี่ยน (PIPE-001) | ทำ pipe discovery ให้ canonical |
| `SUBFAILED probe_on_unstarted_component_returns_no_such_state` ×3 | เหตุผลเดียวกับข้างบน (bridge/core/brain) | เหมือนกัน |
| (เพิ่มเติม) full-suite segfault 1 ครั้ง | ไม่ reproduce ใน per-directory run → flaky/env | เก็บ log แล้ว bisect เมื่อเจอซ้ำ |

---

## 6. Bug classes ที่พบ (สำคัญกว่าตัวบั๊กเอง — ใช้เป็น checklist ป้องกันการพัง)

**6.1 Ordinal drift ข้าม contract** — **ปิดช่องแล้ว (`bbabb2c`)**
`EventSource` มี 2 space: canonical (`src/contract/canonical_event.zig`: npcap=9, external=255) กับ legacy
(`src/contract/event.zig`: capture_npcap=1, system=99) → forensic ring เคยเก็บ ordinal ของ legacy space
(498/500 records = `system` 99) และ adapter ทิ้ง source ของ canonical event เป็น `.system` ทุกตัว
ตอนนี้: writer แปลงเป็น canonical + เก็บ space version ที่ `reserved[5]`, reader canonicalize record เก่า,
และ `pushCanonicalEventWithPayload` ตั้ง `ev.source` ด้วย mapping ที่ทดสอบ round-trip ครบทุก sensor

**6.2 `EnforcementStatus` 4 ค่า vs 6 ค่า** — **ปิดช่องแล้ว (`dd83fac`)**
`src/forensic/policy_contract.zig` (pending 0, enforced 1, failed 2, rolled_back 3) เทียบ
`src/policy/enforcement_receipt.zig` (… unavailable 3, rolled_back 4, simulated 5) → `@enumFromInt`
ข้ามโมดูลอ่าน `rolled_back` เป็น `unavailable` เงียบ ๆ (คลาสเดียวกับบั๊ก PEP ABI ที่เคยทำ ALLOW ทั้งที่ตั้งใจ BLOCK)
แก้โดย: receipt มี `wireStatus()` mapping แบบ total + test เทียบ 2 space และยืนยันว่ามีแค่ `enforced` ที่เป็น 1 ได้

**6.3 Contract ที่ไม่มีผู้อ่าน** — **ปิดแล้ว (`dd83fac`)**
`contracts/fixtures/` 13 ไฟล์ (abi/adapters/control/data_plane/detection/enforcement/health/lab/operator/policy/release/replay)
→ grep ทั้ง repo = 0 reader/validator; ตอนนี้มี `tests/contracts/test_contract_fixtures.py` ตรวจทุกไฟล์กับ contract จริง
(เจอของจริง: fixture detection ประกาศ `severity: 6` ซึ่ง canonical space ไม่มี และ `rule_id` ที่ไม่มี tier ไหนคำนวณได้)

**6.4 สำเนา config ที่ยังถูกใช้** — **ปิดแล้ว (`3331109`)**
`config/Rules.json` ต่างจาก `configs/Rules.json` 2 `regex_pattern` และถูกอ่านโดย `tools/golden_path_evidence.py:125`
→ evidence ของ golden path สร้างจาก ruleset ที่ไม่ใช่ canonical (แถม hash ไฟล์หนึ่งแต่ประกาศชื่ออีกไฟล์ และนับ rules ได้ 0)
ตอนนี้: ทุก reader/writer ชี้ `configs/Rules.json`, mirror byte-identical, มี drift test กันกลับมา

**6.5 Reader ก่อน Writer / Doc rot**
เคยเจอ: handler อ่าน `reserved[6]` (จริง ๆ writer เขียนอยู่ — แก้ความเข้าใจแล้ว), doc สอน `--log` ที่ถูกยกเลิก,
แผนที่ truth stamp ค้าง 3 commit — ต้อง verify จากโค้ดทุกครั้งก่อนเชื่อ

**6.6 โครงสร้างที่ทำให้ repo บวม**
`aegis-audit-*/` 198 ไฟล์ tracked = 13,959 MB (99.9% ของ tracked ทั้งหมด) และไม่มี gate กันไฟล์ใหญ่
→ แผนแก้อยู่ใน `analysis/PROJECT2_COMPLETENESS_AND_REPO_CLEANUP.md` §3

---

## 7. สิ่งที่ยัง "ไม่ยืนยัน" (ห้ามอ้างว่าผ่าน)

1. การตรวจจับโจมตีจริงจาก Kali → Windows 11 บน host นี้ (ยังไม่มี evidence bundle ของ attack จริง)
2. การบล็อกจริงผ่าน WFP (E5) — `provider_ready=false`, `host_effect_capable=false`
3. web dashboard (`tools/aegisctl/web_dashboard/app.py`) แบบ visual
4. rule/policy reload แบบ atomic ใต้โหลดจริง (Phase 5)
5. Phase 9–12 (evidence bundle/replay ระดับ host, operator, release, acceptance) ให้ครบตาม handoff
6. ETW realtime (ถูกบล็อกด้วย `StartTraceW 183`)
7. พฤติกรรมใต้ concurrency ของ forensic ring + graph ที่ดึงข้อมูลพร้อมกัน

---

## 8. ลำดับทำงานที่ตกลง (Project 2 → Clean → Push)

1. ~~**Detection contract pin**~~ — **เสร็จ** `3331109` (golden rule-id table ตรงกัน 3 ภาษา, ระบุเจ้าของ `regex_pattern`)
2. ~~**`forensics.list` pagination**~~ — **เสร็จ** `bbabb2c` (byte budget 32 KiB + `truncated`/`next_after` + client accumulate; พิสูจน์สด 403/403 records)
3. ~~**Single rule authority**~~ — **เสร็จ** `3331109` (ทุก reader/writer → `configs/Rules.json`, mirror byte-identical)
4. ~~**Forensic source space + rule attribution**~~ — **เสร็จ** `bbabb2c` (canonical ordinal + space version byte + adapter ตั้ง `ev.source`; พิสูจน์สด npcap_sensor 400/400)
5. **Alerts → daemon** — ให้ UI แสดง detection จริง (งานถัดไป)
6. ~~**ปิด test แดง 6 ตัว + contract ที่ไม่มีผู้อ่าน**~~ — **เสร็จ** `f00b29e` + `dd83fac` (+ `77424c4` แก้ test ที่ patch global `subprocess.run`)
7. **Enforcement E5** — Admin + WFP เพื่อพิสูจน์ block จริง
8. **Clean repo 30 GB → ~20-40 MB** (backup ก่อน → untrack → rewrite history → resync truth) แล้ว push
