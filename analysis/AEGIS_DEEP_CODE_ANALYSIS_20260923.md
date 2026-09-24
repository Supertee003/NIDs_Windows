# AEGIS Windows-native NIDS/IPS — รายงานวิเคราะห์เชิงลึกสำหรับการพัฒนาต่อ

**วันที่:** 23 กันยายน 2026  
**Baseline ที่อ้างอิง:** `46b93dc`  
**โหมดปัจจุบัน:** Observe-only / qualification  
**Prevention gate:** `CLOSED`  
**คำตัดสิน:** **ยังไม่ production-ready ในฐานะ IPS และยังไม่มีหลักฐานที่อนุญาตให้เปิด prevention gate**

## 1. บทสรุปผู้บริหาร

AEGIS มีโครงสร้างของระบบ NIDS/IPS ที่ค่อนข้างครบในเชิงองค์ประกอบ ได้แก่ Go Nose/Npcap, Zig event pipeline, ETW/FIM/Registry, Python Brain, Rust Policy Enforcement Point (PEP), C/WDK bridge, WFP driver, control plane และ forensic ring อย่างไรก็ตาม คำว่า “มีเส้นทางโค้ด” ไม่เท่ากับ “พิสูจน์ host effect แล้ว”

จาก handoff และการตรวจ source จริง ข้อสรุปที่ปลอดภัยคือ **ระบบผ่านได้เฉพาะ observe-only qualification บางส่วน**. Handoff รายงานว่า RC assembly/checksum และ WFP read-only telemetry ผ่าน แต่ยังระบุเองว่า valid mutation ไม่ได้ถูก execute, `EnforcementReceipt v1` ยังไม่ครบ, query ABI ยังไม่ผ่าน Windows/WDK compile, host postcondition ยังไม่ถูกพิสูจน์ และ post-cleanup absence ยังไม่ถูกพิสูจน์ [1]

จุดที่ขวาง production IPS มีหลายชั้นและเป็นอิสระต่อกัน ดังนี้

1. `enforcement.block` ถูกปิดด้วย gate จึงไม่สามารถสร้าง valid production block ได้ในสถานะปัจจุบัน. หากมีการเปิด gate ด้วยการแก้ global หรือ bypass safety invariant โค้ดจะคืน `ENFORCED` จาก `filter_id` และ tuple ที่ส่งเข้าไป โดยยังไม่มี complete receipt และ provider-backed read-back ที่เพียงพอ [2, §P0.1].
2. Query ปัจจุบันอ่าน shadow state ที่ driver เก็บใน globals ไม่ใช่การ enumerate/read-back จาก WFP provider จริง. API ยังไม่สามารถแสดง `present=false` เป็นผลลัพธ์ที่แยกจาก query error ได้ จึงปิด cleanup proof ไม่ได้ [3, §P0-1].
3. Filter ถูกสร้างด้วย `FWPM_FILTER_FLAG_PERSISTENT` ขณะที่ session เป็น dynamic และ ownership อยู่ใน global เดียวกับ capture path. หลัง restart ยังไม่มี owner metadata, reconciliation หรือ safe handover [3, §P0-2].
4. Mutation boundary ยังไม่ authenticate caller แบบ source-enforced. Device ไม่มี ACL ที่จำกัด, bridge เปิด read/write และ Rust เชื่อ capability/PID ที่ caller ส่งผ่าน FFI [3, §P0-3].
5. Layer/tuple ที่ใช้ block คือ `ALE_AUTH_CONNECT_V4` แบบ remote tuple ขณะที่ approved proof เป็น inbound Kali → Windows. Source ยังไม่พิสูจน์ว่าผลที่ block คือ traffic เดียวกับ proof scope [3, §P0-4].
6. Active ETW callback มี C/Zig record layout ไม่ตรงกัน. ดังนั้น event ID, timestamp, provider, PID และ payload attribution ยังใช้เป็นหลักฐาน production ไม่ได้จนกว่าจะมี normalization boundary และ Windows ABI fixture [4, §P0.1].
7. Operator surface และ wrapper บางตัวสามารถพิมพ์ `BLOCKED`, `PASS` หรือคืน exit code 0 จาก intent, local file, UDP send หรือ static metadata โดยไม่ได้รับ host receipt. นี่เป็นความเสี่ยงด้านความจริงของ control plane โดยตรง [5, §P0].

ดังนั้นสถานะที่ถูกต้องในวันนี้คือ **DETECTION_ONLY / PROVIDER_READY_GATE_CLOSED** ไม่ใช่ `ENFORCED`. RC “PASS” ที่ handoff รายงานควรตีความเป็น packaging/checksum และ observe-only qualification เท่านั้น ไม่ใช่ approval ของ IPS mutation [1]. ไม่มีหลักฐานจากงานนี้ที่ยืนยัน valid block, exact provider postcondition, benign probe ที่ถูกบล็อก, exact cleanup และ `present=false` หลัง cleanup.

## 2. ขอบเขตและความน่าเชื่อถือของหลักฐาน

ตรวจ handoff ก่อนตรวจ source ตามข้อกำหนด และตรวจ source ที่จำเป็นใน workspace `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows`. การตรวจนี้เป็น read-only และไม่มีการแก้ production source ระหว่างการวิเคราะห์

รายงานย่อยที่มีอยู่จริงใน `analysis/` ณ เวลาสังเคราะห์และอ่านได้คือ `agent_native_enforcement.md`, `agent_sensor_nose.md` และ `agent_integration_release.md`. ไฟล์ `agent_zig_policy.md` และ `agent_brain_control_ui.md` **ไม่พบใน filesystem ณ เวลาตรวจ** แม้ผลลัพธ์ย่อยที่ส่งมาได้ระบุ findings และ paths ของสองงานนั้นไว้แล้ว. รายงานนี้จึงใช้ findings จากผลลัพธ์ย่อยในส่วนที่ตรวจสอบซ้ำกับ source ได้ และไม่อ้างว่าได้อ่านไฟล์รายงานสองไฟล์ที่ไม่มีอยู่จริง

การจัดชั้นหลักฐานมีดังนี้

| ชั้นหลักฐาน | ความหมายในรายงานนี้ |
|---|---|
| **Verified source fact** | อ่าน source/config/test จริงและระบุ path:line ได้ |
| **Handoff-reported result** | ผลที่ handoff ระบุว่าเคยเกิดขึ้น แต่ไม่ได้รันซ้ำใน Linux sandbox |
| **Inference** | ข้อสรุปจาก semantics ของ Windows/WFP หรือจากการเชื่อมหลายโมดูล ต้องยืนยันด้วย Windows acceptance test |
| **Unknown** | source และสภาพแวดล้อมปัจจุบันไม่พอจะตัดสิน ห้ามใช้เป็น approval |

สภาพแวดล้อม Linux นี้ไม่มี Zig compiler และจากรายงานย่อยไม่มี Go/Rust/C++/CMake toolchain ที่ใช้ตรวจ Windows native path ได้. จึงไม่มีการอ้างว่า `zig build`, `cargo build`, `go test`, WDK build, DLL export test, driver install หรือ provider enumeration ผ่าน. Binary/DLL ที่มีอยู่ใน workspace ไม่ถูกถือเป็นหลักฐานว่า build จาก source baseline เดียวกันหรือเป็น artifact ที่ signed/trusted.

## 3. Production-readiness decision

| Gate | สถานะที่มีหลักฐาน | คำตัดสิน |
|---|---|---|
| RC assembly/checksum | Handoff รายงาน `RC PASS` และ `RC VERIFY PASS` | ผ่านเฉพาะ self-consistency ของ artifact; ยังไม่ใช่ provenance/signing proof |
| Observe-only WFP/Npcap | Handoff รายงาน read-only event frames และ Npcap attribution | ผ่านในขอบเขตที่ handoff รายงาน; ไม่ใช่ mutation proof |
| Runtime wiring | Daemon source มี pipeline, Go Nose reader, ETW, FIM, Registry และ control startup | มี wiring บางส่วน แต่ health/readiness และ ABI ยังมี gaps |
| 22-rule synthetic validation | Handoff/ผลย่อยรายงาน synthetic qualification | เป็น synthetic evidence; real-sensor matrix ยังไม่ครบ |
| Rust PEP authority isolation | Source ตั้งใจให้ Rust PEP เป็น authority และมี structural tests | แนวทางถูกต้อง แต่ runtime authority และ ACL ยังไม่พิสูจน์ |
| `EnforcementReceipt v1` | Contract มีโครงสร้าง แต่ active response ไม่ serialize ครบ | **ไม่ผ่าน — P0** |
| Provider-backed exact read-back | Query code อ่าน driver globals; ยังไม่ Windows/WDK compiled | **ไม่ผ่าน — P0** |
| Host block postcondition | ไม่ได้ execute valid proof | **ไม่ผ่าน — P0** |
| Exact cleanup | Delete ตาม ID มี แต่ไม่มี post-delete query | **ไม่ผ่าน — P0** |
| Post-cleanup absence | `present=false` แทนไม่ได้ใน current ABI | **ไม่ผ่าน — P0** |
| Driver/policy/release signing | พบ fallback/test-signing และ verifier ที่ไม่ตรวจลายเซ็นจริง | **ไม่ผ่าน — P1** |
| UI/control truthfulness | มี wrapper หลายชุดที่ใช้ local intent/log/UDP/static result | **ไม่ผ่าน — P0/P1** |
| Production approval | Handoff ระบุไม่ granted | **ไม่อนุมัติ** |

**ข้อกำหนดตัดสิน:** ต้องคง `prevention_gate = CLOSED`. การเปิด gate ไม่ใช่ milestone ถัดไป; milestone ถัดไปคือการปิด ABI, receipt, authorization, ownership และ cleanup proof แล้วจึงทำ isolated reversible host proof.

## 4. Architecture และ end-to-end data/control flow

### 4.1 ภาพรวมเชิงตรรกะ

```text
  Network / Windows host sources
  ├─ Go Nose + Npcap
  ├─ ETW native helper
  ├─ FIM native helper
  ├─ Registry watcher
  ├─ WFP read-only event ring
  └─ legacy C++ adapters / named pipes
              |
              v
  Canonical event serialization / source adapters
              |
              v
  Zig ingestion: Nose reader -> event queue -> event processor
              |
              v
  Flow -> signature -> anomaly -> threat tracker
              |
              v
  PolicySet evaluation -> Rust PEP authorization
              |
              +--> ActionDispatcher / control decision
              +--> audit / decision trace / forensic ring
              |
              v
  Intended mutation authority only:
  control pipe -> Zig handler -> Rust PEP -> C bridge -> WFP driver -> WFP provider
              |
              v
  Required proof:
  complete receipt -> provider-backed exact read-back -> benign probe
              |
              v
  cleanup by receipt.filter_id -> provider-backed present=false -> ROLLED_BACK
```

### 4.2 Actual daemon path ที่ตรวจพบ

เส้นทางที่ daemon เรียกจริงไม่ใช่ `runtime_spine` ที่ประกาศเป็น single spine ใน contract module. `src/daemon.zig:322-342` สร้าง `PepEnforcer` และ `ActionDispatcher`; `src/daemon.zig:389-439` สร้าง sensor, pipeline, Nose reader, ETW, FIM และ Registry threads; readiness อยู่ที่ `src/daemon.zig:441-503`. Network ingress ที่ daemon ระบุเป็น canonical คือ Go Nose → named pipe → `nose_reader` และ pipeline queue [6].

ภายใน `src/pipeline/event_processor.zig:47-201` event ถูก copy แล้วผ่าน flow lookup, signature, anomaly, tracker, policy, PEP, action dispatch, audit trace และ forensic append. `src/pipeline/event_processor.zig:237-239` จับ pipeline error เพียง log warning; ไม่ได้สร้าง failure fate/receipt ที่ link กับ event เมื่อ processing ล้มเหลว. Forensic path ปัจจุบันใช้ `forensic_ring.append(... pep_decision ...)` ที่ `:198-200` มากกว่า `appendReceipt()` ที่ validate `EnforcementReceipt` แบบเข้มกว่า ดังนั้น forensic record ที่มี decision ไม่ควรถูกตีความเป็น host effect

### 4.3 Control/mutation path

คำสั่ง `enforcement.block`, `enforcement.verify` และ `enforcement.unblock` ถูกประกาศเป็น privileged/mutation/postcondition commands ใน `src/control/protocol.zig:227-232`. Handler ตรวจ role และ payload แล้วเรียก `pep_bindings`.

อย่างไรก็ตาม `enforcement.block` ที่ `src/control/handler_registry.zig:607-623` ปฏิเสธเมื่อ gate ปิด แต่หลัง gate เปิดจะเรียก `pep.enforceFlow(...)` แล้ว serialize เพียง `status`, `filter_id`, `reason` และ tuple. ไม่มี complete receipt v1 และไม่มี mandatory verify ใน transaction เดียวกัน. `enforcement.verify` ที่ `:510-560` รับ `filter_id` กับ tuple จาก request แล้ว query/compare; ยังไม่ validate receipt identity, provider status, policy/event/trace/audit linkage. `enforcement.unblock` ที่ `:626-652` ลบตาม ID แล้วคืน `CLEANED` โดยไม่ query ซ้ำ

Rust `pep_bindings.zig:151-200` ปัจจุบันส่ง/รับ subset ของ receipt, คืน `null` เมื่อ provider error หรือ `present == 0`, และไม่มี tri-state result สำหรับ absent ที่ยืนยันได้. C/driver query ที่ `drivers/wfp_callout/aegis_wfp.c:374-399` เปรียบเทียบกับ `g_FilterId` และคืน tuple จาก `g_Blocked*` ไม่ใช่ WFP provider enumeration

### 4.4 Data/control separation ที่ต้องรักษา

- **Data plane:** sensor event และ observe-only telemetry ต้องไม่สามารถประกาศ host effect เอง
- **Policy plane:** policy decision เป็น intent/authorization decision ไม่ใช่ proof ว่าระบบปฏิบัติการเปลี่ยน state แล้ว
- **Enforcement plane:** Rust PEP เป็น authority เดียวที่ส่ง mutation ผ่าน authenticated bridge
- **Evidence plane:** receipt, provider status, exact tuple, trace, audit, forensic และ cleanup evidence ต้อง link กันด้วย identity เดียวกัน
- **Operator plane:** UI/CLI ต้องแสดง `REQUESTED`, `SIMULATED`, `FAILED`, `UNAVAILABLE`, `ENFORCED`, `ROLLBACK_PENDING`, `ROLLED_BACK` แยกกัน และต้องไม่อนุมานจาก log หรือ local block list

## 5. File/module ownership และ critical interfaces

### 5.1 ตาราง ownership

ตารางนี้ระบุ owner เชิงสถาปัตยกรรม ไม่ได้หมายความว่า source ปัจจุบัน enforce ownership ครบแล้ว

| Domain | Authoritative modules/files | หน้าที่และข้อมูลออก | สิ่งที่ห้ามทำ / สถานะ |
|---|---|---|---|
| Runtime startup/lifecycle | `src/daemon.zig`, `src/main.zig`, `src/reliability/lifecycle.zig` | สร้าง subsystem, worker, readiness และ shutdown | ต้องไม่มี second startup spine; ปัจจุบันมี concrete list ซ้ำกับ declarative spine |
| Canonical event contract | `src/contract/canonical_event.zig`, `src/contract/event.zig`, `src/contract/nose_contract.zig` | wire schema, event kind, identity และ validation | ต้องเป็น source of truth เดียว; Go enum/schema ยัง drift |
| Go network ingress | `nose/capture.go`, `nose/pipe_writer.go`, `nose/canonical.go` | Npcap packet → canonical 109-byte frame → pipe | ห้ามรายงาน host block; event ID/loss/backpressure ยังไม่ restart-safe |
| Zig Nose ingress | `src/capture/nose_pipe_reader.zig`, `src/pipeline/event_queue.zig` | frame validation, queue ownership และ handoff | ต้อง reject/quarantine duplicate/regressive IDs; ปัจจุบัน log แล้ว submit |
| Windows host sensors | `src/windows/etw_native.c`, `src/windows/etw_realtime.zig`, `src/windows/fim_native.c`, `src/windows/fim.zig`, `src/windows/registry_monitor.zig` | ETW/FIM/Registry observation | ต้อง normalize ABI และ surface loss; ETW C/Zig layout ไม่ตรง |
| Pipeline processing | `src/pipeline/event_processor.zig`, `src/pipeline/event_queue.zig`, `src/pipeline/runtime_state.zig` | flow, detection, anomaly, policy, PEP call, audit, forensic | ไม่ควรกลืน processing failure หรือใช้ raw decision เป็น receipt |
| Detection/rules | `src/detection/*`, `src/core/nids_analyze.zig`, `src/pipeline/rule_loader.zig` | signature/anomaly/rule lifecycle | `nids_analyze` เป็น legacy path ต้อง quarantine หลัง trace ยืนยัน |
| Policy IR/evaluation | `src/policy/policy_ir.zig`, `src/policy/dispatcher.zig`, `src/policy/action_dispatcher.zig` | policy match และ action semantics | policy decision ไม่ใช่ host effect; parser loader ยัง simplified |
| Policy trust/signing | `src/policy/policy_signing.zig`, `src/policy/tier3_state.zig` | signed envelope, key/version/expiry/rollback | ต้อง wire เข้า daemon loader; `AEGIS_FAIL_OPEN=1` ไม่ควรมีใน production build |
| Enforcement authority | `src/policy/pep_bindings.zig`, `src/core/rust_pep.zig`, `rust-src/lib.rs` | Rust PEP FFI, authorization, block/query/unblock | ต้องเป็น authority เดียว; response และ query ยังไม่ใช่ receipt v1/provider proof |
| WFP user bridge | `src/windows/wfp_ioctl.c`, `src/windows/aegis_wfp.c`, `src/windows/win32_io.zig` | DeviceIoControl and exported ABI | ต้องแยก read telemetry/mutation broker และมี export/ACL proof |
| WFP kernel provider | `drivers/wfp_callout/aegis_wfp.c`, `aegis_wfp.h`, `aegis_wfp_callout.c` | WFP add/delete/query and callout | ต้อง enumerate provider จริง, owner metadata, separate IDs, synchronized lifecycle |
| C++ bridge/legacy adapters | `bridge/aegis_adapter.cpp`, `aegis_ipc.cpp`, headers | native IPC/adapter compatibility | ต้องไม่ถูกอ้างเป็น canonical evidence หากยัง synthetic/ABI ไม่ตรง |
| Control plane | `src/control/protocol.zig`, `authorization.zig`, `handler_registry.zig`, `audit.zig` | command envelope, auth, handler, audit | mutation success ต้องอิง receipt/postcondition ไม่ใช่ filter ID |
| Forensics | `src/forensic/forensic_pipeline.zig`, `decision_trace.zig` | hash chain/ring/receipt linkage | `appendReceipt` ต้องเป็น path หลักของ confirmed enforcement |
| Operator/UI/CLI | `tools/aegisctl.py`, `tools/aegisctl/commands/*`, `scripts/*`, `mouth/*` | health/status/block display and operations | ห้าม local file/UDP/log infer host effect |
| Release/deployment | `tools/release_candidate.py`, `deploy_windows.py`, `installer*`, `scripts/install*` | build/package/install/rollback | ต้อง fail closed on signing/build/test/provenance failure |
| Tests/proof | `tests/wfp/*`, `tests/ips/*`, `tests/runtime/*`, `scripts/run_*` | static, safe probe, observe-only, eventual host proof | static/negative tests ไม่ใช่ valid IPS proof |

### 5.2 Critical interfaces

| Interface | Current producer → consumer | Contract ที่ต้องมี | Current risk |
|---|---|---|---|
| Canonical event wire | Go Nose → Zig reader | magic/version/size, enum ordinals, non-zero identity, monotonic generation, loss marker | Go enum drift, process-local ID, IPv6 truncation, no cross-restart gap semantics |
| ETW event record | C native helper → Zig callback | shared packed layout หรือ C normalization | C record เริ่ม `event_id:u32`; Zig อ่านเป็น `timestamp_ns:i64` |
| Pipeline queue | sensors → `event_queue` → processor | bounded ownership, backpressure/loss, shutdown | queue หลักมี mutex แต่ sensor globals/health บางส่วนไม่ synchronized |
| Control envelope | client → named control pipe → protocol/handler | authenticated caller, request_id/nonce, role/capability, response schema | audit/error JSON escaping และ caller identity binding ยังไม่พอ |
| PEP FFI | Zig → Rust `aegis_pep_enforce/query/unblock` | versioned fixed/length-delimited ABI, full receipt and tri-state query | subset response, query `null` conflates absent/error, no exact tuple read-back |
| WFP IOCTL | Rust/C bridge → device → driver | ACL, authenticated broker, exact input/output sizes, provider status | open device access broad; source lacks restrictive SDDL and provider enum |
| WFP provider object | driver → WFP engine | owner GUID, layer/direction/conditions, restart-safe identity | persistent filter + dynamic session + globals; capture/proof ID collision |
| Enforcement receipt | PEP/provider → control/forensic/UI | v1 fields: request/event/policy/decision/status/provider/filter/host confirmation/trace/audit | active block response omits most fields; forensic pipeline often stores decision only |
| Cleanup | receipt.filter_id → delete → query same ID | tri-state `present=false` with provider status; uncertain = `ROLLBACK_PENDING`/degraded | current unblock returns `CLEANED` immediately |
| Health projection | daemon/control snapshot → CLI/UI/Mouth | source, generated_at, age, authority, freshness and lifecycle state | wrappers infer from logs/local files and health can return 0 while degraded |
| Release evidence | source commit → build → signed artifact → installer | immutable manifest, digest, Authenticode/catalog, clean tree, toolchain result | verifier mostly checks self-written SHA256SUMS/presence |

## 6. Findings ระดับ P0 — ต้องปิดก่อน production IPS

### P0-1 — `ENFORCED` ถูกคืนก่อน complete receipt และ provider postcondition

**Path/line:** `src/control/handler_registry.zig:607-623`; `src/policy/pep_bindings.zig:151-187`; `rust-src/lib.rs:179-186,495-532`

**ผลกระทบ:** ในสถานะปัจจุบัน gate ปิดจึงถูก fail-closed. แต่หาก gate ถูกเปิดโดยวิธีใดก็ตาม handler สามารถคืน `status=ENFORCED` จาก `filter_id` ที่ PEP คืนมา โดยยังไม่มี `receipt_version`, `request_id`, `event_id`, `policy_id`, `provider`, `host_effect_confirmed`, `trace_id`, `audit_id` และไม่มี mandatory post-block query. Downstream อาจตีความ policy decision หรือ adapter success เป็น host effect

**หลักฐาน:** `handler_registry.zig:610-614` ปฏิเสธ gate ที่ปิด; `:617` เรียก `enforceFlow`; `:623` serialize เพียง status/filter/reason/tuple. `enforceFlow` คืน struct ที่มีเพียง decision/reason/quota/signed_by/filter_id [2].

**วิธีแก้:** ทำ transaction เดียวที่รับ signed/trusted request, capture pre-state, เรียก Rust PEP, query exact filter ID ผ่าน provider-backed ABI, compare tuple และ provider status, สร้าง receipt v1 ครบทุก field แล้วจึงคืน `ENFORCED`. Failure ทุกแบบต้องคืน structured failure หรือ pending state ห้ามคืน success จาก filter ID

**Acceptance test:** fake provider ที่คืน add success แต่ query tuple mismatch ต้องได้ `POSTCONDITION_FAILED`; provider query unavailable ต้องไม่มี `ENFORCED`; valid path ต้อง serializeและ validate field ทั้ง 11 ตาม handoff และ `appendReceipt` ต้องรับ event identity เดียวกันเท่านั้น

### P0-2 — Query เป็น shadow state ไม่ใช่ independent WFP provider read-back และไม่มี absence result

**Path/line:** `drivers/wfp_callout/aegis_wfp.c:374-399`; `rust-src/lib.rs:338-349,577-604`; `src/policy/pep_bindings.zig:195-200`

**ผลกระทบ:** `AegisWfpQueryFilter` ตรวจ `requested_filter_id == g_FilterId` แล้วคัดลอก `g_BlockedIp`, `g_BlockedPort`, `g_BlockedProtocol`. ไม่ได้เรียก `FwpmFilterGetById0`, `FwpmFilterEnum0` หรือ provider enumeration. หลัง cleanup ฝั่ง Rust/Zig แปลง `present=0` หรือ not found เป็น error/null จึงไม่สามารถพิสูจน์ `present=false` ได้

**หลักฐาน:** driver query source ไม่มี WFP provider lookup และตั้ง `provider_status` จาก local state. Rust query ยอมรับเฉพาะ `rc==0`, ID ตรง และ `present != 0`. Handoff เองระบุ query work ยังไม่ Windows/WDK compiled และ first implementation อ่าน driver-owned state [1, §6].

**วิธีแก้:** กำหนด result แบบสามสถานะ `PRESENT`, `ABSENT`, `QUERY_ERROR` พร้อม provider status. Query ต้อง enumerate/read object จริงและตรวจ conditions/layer/provider owner. เพิ่ม query ก่อน add, หลัง add, หลัง benign probe และหลัง delete

**Acceptance test:** filter ID ที่ไม่มีใน provider ต้องได้ `ABSENT` ไม่ใช่ `QUERY_ERROR`; filter ที่ driver global ยังมีแต่ provider ไม่มีต้อง fail; หลัง delete ต้องได้ `ABSENT` และมี provider status ที่ตรวจสอบได้

### P0-3 — Persistent filter ไม่มี ownership/reconciliation ที่ปลอดภัยต่อ restart

**Path/line:** `drivers/wfp_callout/aegis_wfp.c:245-289,315-399`; `drivers/wfp_callout/aegis_wfp_callout.c:221-265`

**ผลกระทบ:** add path เปิด dynamic session แต่สร้าง filter แบบ `FWPM_FILTER_FLAG_PERSISTENT`. Identity และ tuple ถูกเก็บใน globals. `g_FilterId` ยังถูกใช้ร่วมระหว่าง capture/proof path. หลัง driver/service restart filter ที่ persistent อาจยังอยู่ แต่ global identity หาย หรือ ID ใหม่ถูกเขียนทับ ทำให้ cleanup ผิด object หรือ orphaned filter

**หลักฐาน:** `:247` ตั้ง dynamic session, `:277` ตั้ง persistent flag, `:284-287` เขียน global; `:327` unblock อนุญาตเฉพาะ global ID. ไม่มี owner GUID, generation, startup reconciliation หรือ enumeration ของ AEGIS-owned objects

**วิธีแก้:** เลือก dynamic proof session หรือออกแบบ persistent ownership ให้ชัดเจน. เพิ่ม provider/sublayer GUID, owner metadata, boot/session generation, แยก `capture_filter_id`, `proof_filter_id`, `provider_callout_id`, `runtime_callout_id`. ทำ startup reconciliation และ idempotent cleanup

**Acceptance test:** add → restart service/driver → enumerate เฉพาะ AEGIS owner → query exact ID/tuple → delete → query absent. Concurrent add สอง request ต้องไม่เขียนทับ identity และ cleanup ต้องไม่ลบ capture filter

### P0-4 — Mutation boundary ไม่ authenticate caller และ device ACL กว้างเกินไป

**Path/line:** `drivers/wfp_callout/aegis_wfp.c:62-65`; `src/windows/wfp_ioctl.c:107-115`; `rust-src/lib.rs:452-460`; `drivers/minifilter/aegis_minifilter_comm.c:228-259`

**ผลกระทบ:** caller ที่เข้าถึง device/DLL อาจปลอม `caller_pid` และ capability mask ผ่าน FFI. PEP จึงเป็นเพียงการตรวจค่าที่ caller ส่ง ไม่ใช่ authentication ของ process/token. Mutation boundary อาจถูกเรียกนอก control-plane ที่กำหนด

**หลักฐาน:** driver ใช้ `IoCreateDevice` โดย source ไม่กำหนด restrictive security descriptor; bridge เปิด `GENERIC_READ|GENERIC_WRITE`; Rust ตรวจ bit ใน `req.ctx.caller_capability_mask`; minifilter port ใช้ `FLT_PORT_ALL_ACCESS`

**วิธีแก้:** ใช้ restrictive SDDL/`IoCreateDeviceSecure`, แยก telemetry read handle กับ privileged broker, ตรวจ access token/integrity/process identity ใน broker, bind request nonce/capability กับ audit identity, pin DLL absolute path และ signature/hash

**Acceptance test:** standard user, low-integrity process, forged PID/capability, direct DLL caller และ unauthorized named-pipe client ต้องถูกปฏิเสธ; privileged service account ที่ถูกต้องเท่านั้นจึงสร้าง request ได้ และ audit ต้องบันทึก authenticated identity

### P0-5 — WFP layer/direction ไม่ตรงกับ approved inbound proof

**Path/line:** `drivers/wfp_callout/aegis_wfp.c:251-275`; `drivers/wfp_callout/aegis_wfp_callout.c:167-171,213-220`; `rust-src/lib.rs:495-505`

**ผลกระทบ:** block ใช้ `FWPM_LAYER_ALE_AUTH_CONNECT_V4` และ remote IP/port/protocol ซึ่งเป็น semantics ของ outbound connect. Observe callout ใช้ `FWPM_LAYER_INBOUND_TRANSPORT_V4`. Approved proof คือ Kali `192.168.126.10` → Windows `192.168.126.1`, TCP/49153. Source ยังไม่พิสูจน์ว่า mutation filter บล็อก inbound destination ที่ต้องการ ไม่ใช่ outbound connection อื่น

**หลักฐาน:** request ส่งเพียง remote tuple; driver ตั้ง layer ALE connect และไม่มี local/direction/interface/app condition. Handoff ต้องการ exact destination tuple [1, §5]

**วิธีแก้:** เลือก WFP layer ที่ตรงกับ inbound proof และกำหนด local/remote tuple, protocol, direction และ scope ครบ. Query ต้องอ่าน conditions จาก provider object ไม่ใช่ตรวจเฉพาะสามค่าใน global

**Acceptance test:** exact Kali→Windows TCP/49153 ถูกบล็อก, TCP port อื่นและ UDP ไม่ถูกบล็อก, outbound flow ที่ไม่อยู่ใน scope ไม่เปลี่ยน behavior, provider query แสดง conditions/layer ตรงกับ receipt

### P0-6 — ETW C/Zig ABI ไม่ตรงกัน ทำลาย event attribution

**Path/line:** `src/windows/etw_native.c:20-38,55-89`; `src/windows/etw_realtime.zig:149-180,896-948`; `src/pipeline/telemetry_threads.zig:55-82`

**ผลกระทบ:** C record เริ่มด้วย `event_id:u32`, version/channel/level/opcode/task/keyword และ timestamp; Zig struct ที่ callback รับเริ่มด้วย `timestamp_ns:i64`, `provider_guid[16]`, `event_id:u16`. Pointer เดียวกันจึงถูกอ่านคนละ offset. Timestamp, provider, event ID, PID และ variable payload ไม่สามารถใช้เป็นหลักฐานที่เชื่อถือได้

**หลักฐาน:** ไม่มี translation/copy layer และไม่มี `sizeof/offsetof` cross-language assertion. `telemetry_threads` ใช้ event ID และ timestamp จาก struct ที่ layout ไม่ตรง

**วิธีแก้:** สร้าง shared C ABI header หรือ C normalization function ที่แปลง native record เป็น fixed Zig-owned record. กำหนด packing, field widths และ payload length ใน schema เดียว

**Acceptance test:** Windows fixture ที่มี known provider GUID, event ID, timestamp, PID และ payload ต้องได้ค่าเดียวกันใน C, normalization, Zig และ forensic record; compile gate ต้อง fail เมื่อ `sizeof/offsetof` drift

### P0-7 — Python/CLI mutation และ synthetic tools สามารถรายงานผลสำเร็จโดยไม่มี host proof

**Path/line:** `tools/aegisctl/commands/network.py:13-33,36-72`; `scripts/aegis_block.py:50-69,133-140`; `scripts/aegis_unblock.py:35-49,110-117`; `tools/aegisctl/commands/canary.py:24-35`; `tools/aegisctl/commands/simulate.py:35-51`

**ผลกระทบ:** `cmd_block_add` ไม่ตรวจ response/receipt จาก `control_request` แล้วเขียน `blocked_ips` และพิมพ์ `BLOCKED`; remove/clear แก้ local state โดยไม่ส่ง authoritative cleanup. UDP send success ถูกใช้เป็น “request sent/OK”. Canary สร้าง PASS โดยไม่ส่ง traffic ไม่อ่าน receipt; simulation คืน 0 จากข้อความจำลอง

**หลักฐาน:** source ตาม paths ข้างต้นไม่มี guard ที่ต้องมี `response.ok`, receipt v1, filter ID และ postcondition ก่อนพิมพ์ success

**วิธีแก้:** ทำ control plane เดียวเป็น mutation authority. Wrapper ทุกตัวต้องรอ structured response และคืน non-zero เมื่อ control unavailable, receipt failed, filter ID หาย หรือ postcondition false. แยกชื่อ/สถานะ `SIMULATED`, `REQUESTED`, `ENFORCED`, `ROLLED_BACK`; ปิด legacy local mutation หรือให้ต้องใช้ flag unsafe ที่ชัดเจน

**Acceptance test:** mock control unavailable/failed/incomplete receipt ต้องไม่แก้ local stateและต้องคืน non-zero; valid response ที่มี receipt ครบเท่านั้นจึงแสดง `ENFORCED`; canary ต้องติดป้าย synthetic และห้ามเป็น release approval

### P0-8 — Health/authority exit code อาจทำให้ automation ผ่านทั้งที่ degraded

**Path/line:** `tools/aegisctl.py:247-279,790-801` ตามผลตรวจ control/UI

**ผลกระทบ:** `cmd_health` คืน 0 เมื่อ degraded หากไม่ได้ใช้ `--strict`; authority command คืน 0 แม้ invariant ถูกละเมิด. CI/monitoring จึงอาจเดินหน้าต่อทั้งที่ enforcement unavailable หรือ runtime degraded

**หลักฐาน:** branch ใน `cmd_health` คืน non-zero เฉพาะ strict JSON case; ผลย่อยยืนยัน behavior นี้และพบ authority exit-code seam

**วิธีแก้:** กำหนด exit-code contract เดียว: degraded, unknown, stale, unavailable, failed และ invariant violation ต้อง non-zero ใน operator/CI mode. เพิ่ม `--observe-only` สำหรับการยอมรับสถานะที่คาดไว้โดยต้องแสดงชัดเจน

**Acceptance test:** matrix ของ payload `RUNNING`, `DEGRADED`, `UNKNOWN`, stale snapshot, gate closed และ provider unavailable ต้องให้ exit code ตรง contract เดียวกันทั้ง CLI, service check และ CI

## 7. Findings ระดับ P1 — ต้องแก้ก่อน qualification ที่เชื่อถือได้

### P1-1 — Receipt validation อ่อนกว่าข้อกำหนด v1

**Path/line:** `src/policy/enforcement_receipt.zig:29-47`; `src/forensic/forensic_pipeline.zig:123-147`; `tools/aegisctl/contracts.py:49-64`

**ผลกระทบ:** `validate()` ไม่บังคับ `policy_id != 0` และ `decision == block` ในทุก confirmed case. `appendReceipt()` ยังยอม policy ID ศูนย์ในเงื่อนไขบางกรณี. Python projection ยอม version 0 และไม่บังคับ policy/decision ตาม handoff. Evidence consumer จึงอาจรับ receipt ที่ link ได้แต่ไม่ใช่ confirmed block

**หลักฐาน:** receipt `isSuccess()` และ `validate()` ตามบรรทัดข้างต้น; test ในไฟล์เดียวกันมี simulated receipt ที่ `validate()` ผ่าน

**วิธีแก้:** แยก schema `DecisionReceipt` กับ `EnforcementReceipt v1` ให้ชัด. Confirmed enforced ต้องบังคับ version 1, decision block, policy non-zero, provider, filter, host confirmation, trace/audit และ event/request identity. Python/Zig/Rust ใช้ generated fixture เดียวกัน

**Acceptance test:** malformed receipt ทุก field ต้องถูก reject; simulated/observe receipt ห้ามถูก serialize เป็น `ENFORCED`; cross-language round-trip ต้องคงค่าและ reject version 0

### P1-2 — Signed policy module ไม่ถูก wire เข้ากับ daemon JSON loader

**Path/line:** `src/policy/policy_signing.zig:1-18,125-167`; `src/daemon.zig:182-312`; `src/policy/policy_ir.zig:76-88`

**ผลกระทบ:** signed policy มี implementation แต่ daemon โหลด `configs/policies.json` โดยตรงและไม่ได้เรียก `verifyPolicy`/`verifyPolicyWithStore`. Active policy มี `trusted=false` โดย default; privileged action จึงถูก escalate/contain และ real policy-driven IPS ไม่ reach ได้. Fail-safe นี้ปลอดภัยกว่า bypass แต่หมายความว่า “policy engine พร้อม enforce” ยังไม่เป็นจริง

**วิธีแก้:** กำหนด signed envelope เป็น input เดียว, load trust store, verify key/expiry/rollback floor ก่อน set `trusted=true`, persist rollback floor แบบ atomic และ reject unsigned privileged policy

**Acceptance test:** unsigned block policy ต้องไม่เรียก mutation; valid signed policy จึงถูกโหลด; tampered/unknown key/expired/rollback policy ต้องถูก reject และมี audit reason

### P1-3 — Capability mask และ receipt owner ถูก hard-code/mไม่ bind กับ runtime authority

**Path/line:** `src/control/handler_registry.zig:617,646`; `src/pipeline/runtime_state.zig:87-91`; `src/pipeline/event_processor.zig:157-164`

**ผลกระทบ:** control handler ส่ง capability `1` และ `caller_pid` จาก context แทน `g_runtime_capability_mask`/authenticated runtime owner. เมื่อ gate เปิด request อาจใช้ authority context ผิด หรือ cleanup ถูกสั่งโดยผู้ถือ ID ที่ไม่ใช่เจ้าของ receipt

**วิธีแก้:** สร้าง authenticated request context จาก supervisor/broker, ใช้ runtime capability mask ที่ provisioned, require non-zero unique request ID/nonce, บันทึก owner ใน receipt และ bind unblock กับ receipt owner/audit

**Acceptance test:** wrong capability, forged PID, replayed request ID และ cleanup จาก session อื่นต้องถูก reject; correct owner ผ่านได้และทุก ID ตรงกันใน audit/receipt

### P1-4 — มี duplicate/ declarative runtime spine ที่ไม่ตรงกับ daemon path

**Path/line:** `src/contract/runtime_spine.zig:85-147`; `src/daemon.zig:322-439`; `src/policy/dispatcher_phase_b.zig:19-29`; `src/core/legacy_removal.zig`; `src/core/nids_analyze.zig`

**ผลกระทบ:** `runtime_spine` ประกาศ Event Fabric → dispatcher เป็น canonical single spine แต่ daemon ใช้ `event_queue`/`event_processor`/`action_dispatcher`; `dispatcher_phase_b` import adapters จาก tests/integration และไม่ได้อยู่ใน startup path. `nids_analyze`/legacy capture ยังถูก import บางจุด. Unit/declarative test อาจให้ความรู้สึกว่า golden path ครบทั้งที่ production graph ไม่ได้ execute path เดียวกัน

**วิธีแก้:** เลือก production spine เดียว. ทางเลือกที่แนะนำคือทำ daemon → Nose/Event Fabric → canonical dispatcher เป็น path เดียว แล้ว generate registry จาก source เดียว หรือ demote runtime_spine/phase B เป็น proof-only อย่างชัดเจน. ลบ imports production จาก `src/tests/integration` และ quarantine legacy path หลัง trace Windows ยืนยัน

**Acceptance test:** build graph/trace test ต้องพิสูจน์ว่า one event มี path เดียว, มี event/trace ID เดียวจาก source ถึง forensic, ไม่มี direct legacy capture และไม่มี production import จาก tests

### P1-5 — Global state และ pointer/slice lifetime ไม่ใช้ synchronization protocol เดียว

**Path/line:** `src/pipeline/runtime_state.zig:73-114`; `src/capture/nose_contract.zig:49-89`; `src/control/state_machine.zig:272-303`; `src/pipeline/rule_loader.zig:107-121`; `src/forensic/forensic_pipeline.zig:18-21`

**ผลกระทบ:** counters, gate, PEP availability, fabric pointer และ runtime subsystem slices ถูกใช้ข้าม worker/control threads. `state_machine` คืน pointer/slice หลัง unlock; rule reload ไม่ทำลาย retired automaton เพื่อเลี่ยง UAF แต่ leak ต่อ daemon lifetime. Shutdown/submit/pop และ snapshot/update อาจ race หรือให้ข้อมูลไม่สอดคล้อง

**วิธีแก้:** ใช้ atomic สำหรับ scalar, mutex/owner object สำหรับ composite state, snapshot-copy ภายใต้ lock และ epoch/refcount สำหรับ ruleset. แทน global gate ด้วย `ProofGate{state, scope, expiry, nonce, owner}`

**Acceptance test:** stress block/health/reload/shutdown พร้อม TSAN-equivalent/Windows concurrency test; ต้องไม่มี UAF, pointer escape, stale scope, lost update หรือ unbounded ruleset leak

### P1-6 — Cross-language WFP ABI layout drift

**Path/line:** `drivers/wfp_callout/aegis_wfp.h:73-103`; `src/windows/wfp_ioctl.c:66-103`; `src/policy/wfp_ioctl.zig:37-60,205-225`

**ผลกระทบ:** C `AEGIS_RING_STATS` 24 bytes แต่ Zig `WfpRingStats` 16 bytes. Packed C event header 44 bytes แต่ Zig extern layout มีแนวโน้ม 48 bytes/offset ต่างกัน. Telemetry stats และ event parsing อาจเสียหายแม้ read-only qualification จะดูผ่านจากบาง path

**วิธีแก้:** shared header/generated schema หรือ C normalization. เพิ่ม `sizeof`, `offsetof`, `@sizeOf`, `@offsetOf`, Rust `size_of/offset` fixtures และ buffer length tests. Build ต้อง link driver, C, Rust, Zig จริงใน Windows CI

**Acceptance test:** compile-time assertions และ runtime known-vector round-trip ทุก field; output buffer mismatch ต้อง fail explicitly ไม่อ่าน partial struct

### P1-7 — WFP/C bridge lifecycle, callout IDs และ concurrency ไม่ปลอดภัย

**Path/line:** `drivers/wfp_callout/aegis_wfp_callout.c:166-265`; `drivers/wfp_callout/aegis_wfp.c:23-41,278-371`; `rust-src/lib.rs:277-357`; `bridge/aegis_ipc.hpp:232-294`

**ผลกระทบ:** provider callout ID/runtime callout ID/filter ID ใช้ globals ทับกัน; failure cleanup อาจลบผิด object. Rust adapter โหลด DLL/open ทุก enforcement call แต่ Drop ไม่เรียก close. C++ shared ring อ้าง thread-safe แต่ plain counters ไม่มี lock/atomic; shutdown อาจ destroy ขณะ producer/consumer ใช้

**วิธีแก้:** แยก IDs และ lifecycle state, serialize WFP mutation, explicit adapter singleton/close ก่อน unload, lock/atomic queue และ refcount shutdown

**Acceptance test:** failure injection ทุก WFP API, repeated load/open/close 10,000 รอบ, concurrent block/unblock/restart และ queue shutdown stress ต้องไม่ leak/ID overwrite/UAF

### P1-8 — Named pipe, FIM และ ETW lifecycle มี hang/loss/use-after-free risks

**Path/line:** `bridge/aegis_ipc.cpp:75-227`; `src/windows/fim_native.c:26-124`; `src/windows/fim.zig:111-186`; `src/windows/etw_native.c:171-207`; `src/capture/nose_pipe_reader.zig:133-157,235-249`

**ผลกระทบ:** bridge เปิด overlapped pipe แต่ใช้ NULL `OVERLAPPED` และตรวจ `CreateFile` ผิด sentinel. FIM native buffer 64 KiB แต่ Zig poll 16 KiB; overflow ถูก clear/drop. Stop timeout อาจ free FIM session ขณะ worker ยังใช้. Nose reader กลับไป blocking read หลัง connect; idle/partial client อาจทำ supervisor join ค้าง. ETW callback registration/stop/lifecycle และ `StopTrace` usage ยังต้อง compile/verify

**วิธีแก้:** เลือก synchronous I/O อย่างถูกต้องหรือ implement overlapped event/cancel ครบ, ตรวจ `INVALID_HANDLE_VALUE`, align FIM buffer/record boundaries, cancel+join ก่อน free, bounded shutdown และ explicit loss counters

**Acceptance test:** idle/partial pipe shutdown จบภายใน deadline; FIM burst >16 KiB ได้ loss/degraded marker ไม่เงียบ; callback-after-stop ไม่เกิด; repeated start/stop ไม่มี handle/session leak

### P1-9 — Nose identity, provenance, backpressure และ health ไม่ production-grade

**Path/line:** `nose/capture.go:40-42,184-190,213-223,242-260`; `nose/pipe_writer.go:47-67,116-147`; `src/capture/nose_pipe_reader.zig:255-333`; `src/pipeline/event_queue.zig:70-103`; `src/daemon.zig:441-500`

**ผลกระทบ:** event ID reset เมื่อ Go process restart; `UnixNano()` ถูกใส่ใน field ที่ชื่อ MonotonicNS; IPv6 เก็บเพียง 4 bytes; hash เป็น FNV-like ไม่ใช่ SHA-256 prefix ตาม comment. Writer synchronous ไม่มี deadline/queue และ capture ignore `Send` result; reader log duplicate/regression แต่ยัง submit. Canonical-to-IpcEvent ทิ้ง source/session/layer/pipe/process/node/confidence. Readiness ไม่รอ producer connected จึงอาจรายงาน RUNNING ขณะไม่มี capture

**วิธีแก้:** เพิ่ม producer generation/boot UUID + sequence, reject/quarantine duplicate/regression และส่ง gap/loss marker; แยก wall clock กับ monotonic; preserve provenance; bounded cancellable writer; health แยก pipe server, producer connected, capture active และ last event

**Acceptance test:** restart/reconnect property test ไม่มี accepted duplicate identity; slow reader ไม่ทำให้ capture block เกิน deadline; every dropped range มี marker; round-trip provenance ครบ; health ลดเป็น degraded เมื่อ producer disconnect

### P1-10 — Registry/FIM/ETW source evidence ไม่ถูก attribution ครบ

**Path/line:** `src/windows/registry_monitor.zig:64-91,143-236`; `src/pipeline/telemetry_threads.zig:126-177`; `src/windows/fim_native.c:111-125`; `src/windows/etw_native.c:69-82`

**ผลกระทบ:** Registry emits root `value_changed`, maps ทุก event เป็น `dns_query`, ไม่มี exact path/value/rule และ matching case-sensitive ทั้งที่ Windows Registry case-insensitive. FIM overflow/record boundary loss เงียบ. ETW/FIM/Registry IDs เป็นศูนย์/global metric snapshot. Evidence rule จึงอาจผิด source หรือขาด event identity

**วิธีแก้:** normalize case, preserve exact changed key/value/rule ID, map `.reg_change`, bounded queue/drop counter, per-record length validation, authoritative ID minting boundary และ reject zero IDs

**Acceptance test:** mutate Run/Services/SAM fixtures และ assert exact key/value/rule/event kind; malformed chained FIM record ไม่ข้าม boundary; ทุก sensor event มี non-zero unique ID/source

### P1-11 — Release, installer, signing และ deployment gates ให้ false green ได้

**Path/line:** `tools/release_candidate.py:138-158,207-237`; `tools/installer.py:37-117`; `installer.nsi:5-135`; `tools/deploy_windows.py:44-155`; `scripts/install_drivers.bat:100-228`; `tools/upgrade_rollback.py:76-206`

**ผลกระทบ:** RC verifier ตรวจ SHA256SUMS/presence ที่สร้างเอง แต่ไม่ตรวจ clean-tree provenance, Authenticode, catalog/driver signature หรือ cryptographic `signatures.json`. Installer หลายรุ่น hard-code version/commit และ semantics preserve data ไม่ตรงกัน. Deploy อาจเดินหน้าหลัง test/install failure. Driver installer มี test-signing/self-signed fallback และ warning continuation. Rollback เป็น config/data ไม่ใช่ WFP filter/service state และไม่ atomic

**วิธีแก้:** canonical installer เดียว, clean-tree gate, immutable build manifest, SHA-256 cross-check, Authenticode/catalog/signtool verification, fail on missing signing/tool/test, atomic install/rollback และ snapshot WFP pre-state/receipt/provider state

**Acceptance test:** ลบ/เปลี่ยน artifact, dirty tree, wrong signer, failed WDK build, missing required path และ failed install ต้องทำให้ release non-zero และหยุด; install/uninstall/rollback ต้อง preserve data/trust/audit/forensics และ verify filter state แยกต่างหาก

### P1-12 — Operator state projection ไม่ครบและ stale state อาจถูกแสดงเป็น readiness

**Path/line:** `tools/aegisctl/contracts.py:49-84`; `tools/aegisctl/commands/dashboard.py:31-55`; `scripts/Dashboard.py:47-49`; `scripts/aegis_status.py:86-96,170-176`; `mouth/windows_sec_monitor.rs:497-513,603-619,899-905`

**ผลกระทบ:** projection มีเพียง OBSERVE_ONLY/ENFORCEMENT_READY/ENFORCEMENT_UNAVAILABLE ไม่ครบ lifecycle ที่ handoff ต้องการ. Dashboard นับ policy Block/Drop เป็น blocks; Mouth นับ log text “Block/Drop” แม้ไม่มี receipt. UI อาจแสดง READY TO ENFORCE หรือ ACTIVE จาก stale/local evidence

**วิธีแก้:** single `RuntimeSnapshot` ที่มี generated_at/age/source/authority/freshness TTL และ states `DETECTION_ONLY`, `PROVIDER_READY_GATE_CLOSED`, `ENFORCEMENT_PROOF_ACTIVE`, `ENFORCED`, `ROLLBACK_PENDING`, `ROLLED_BACK`, `DEGRADED`. UI อ่าน control-plane snapshot เท่านั้น

**Acceptance test:** stop daemon, stale snapshot, receipt missing, gate closed, provider unavailable และ cleanup pending ต้องถูกแสดงตาม state ที่ถูกต้อง ไม่มี dashboard counter ใดเรียก decision ว่า host block

## 8. Findings ระดับ P2 — ต้องแก้เพื่อ correctness และ maintainability หลัง P0/P1

### P2-1 — Policy parser/semantics ไม่ตรงกับ IR เต็มรูปแบบ

**Path/line:** `src/daemon.zig:254-298`; `src/policy/policy_ir.zig:61-67,133-150`; `src/policy/policy_engine.zig`

**ผลกระทบ:** daemon loader alloc เพียง predicate/clause แรกและ map `gte` เป็น `gt`. `evalPred` มี simplified `in` และ mixed int/string eq/ne. Policy JSON ที่มีหลาย clause/predicate อาจ match ไม่เหมือน signed IR

**วิธีแก้:** ใช้ parser/IR compiler กลาง, รองรับทุก clause/operator/precedence และไม่ silently downgrade unknown operator

**Acceptance test:** golden matrix สำหรับ AND/OR, `in`, eq/ne int/string, gte และ first-match/priority ต้องตรงกันระหว่าง JSON loader, IR evaluator และ signed policy

### P2-2 — JSON/error serialization และ file state ไม่ atomic/escaped ครบ

**Path/line:** `src/control/handler_registry.zig:67-79,180-224`; `tools/aegisctl/utils.py:28-30,56-69,614-615`; `tools/config_validator.py:64-112`; `scripts/aegis_alerts.py:115-120`

**ผลกระทบ:** error envelope interpolate string โดยไม่รับประกัน JSON escaping; state/audit/ack เขียนตรงโดยไม่มี lock/atomic replace. Concurrent operator actions อาจทำให้ state เสียหรือ audit identity ไม่คงที่

**วิธีแก้:** ใช้ JSON writer ที่ escape field, temp file + fsync + atomic replace, lock/recovery และ path containment

**Acceptance test:** quote/newline/backslash ใน error, concurrent writers, crash ระหว่าง replace และ recovery จาก temp file ต้องไม่ทำให้ JSON เสียหรือเปลี่ยน identity

### P2-3 — Packet/parser และ C++ adapter boundary มี correctness gaps

**Path/line:** `bridge/aegis_packet_parser.hpp:151-155,249-315`; `bridge/aegis_adapter.cpp:427-448`; `nose/capture.go:213-223`

**ผลกระทบ:** parser ไม่จำกัด IPv4/UDP ตาม declared length และไม่ handle non-first fragments. C ABI poll ตรวจ capacity ต่อ frame ไม่ใช่ capacity รวม; อาจเขียนเกินเมื่อ `maxOut > 1`. IPv6 ถูก truncate

**วิธีแก้:** validate total/UDP length, fragments, IHL/options, unaligned input; check multiplication overflow/total capacity; introduce full IPv6 sidecar or explicit truncated status

**Acceptance test:** malformed packet vectors, fragment vectors, canary buffer C ABI และ IPv6 known vectors ต้องผ่านโดยไม่มี OOB/false attribution

### P2-4 — Legacy C++ IPC และ adapters เป็น schema/semantics คนละชุด

**Path/line:** `bridge/aegis_ipc.hpp:64-109`; `bridge/aegis_ipc.cpp:75-229`; `bridge/aegis_adapter.cpp:213-290`; `src/windows/windows_adapters.zig:135-170,255-287,377-410`

**ผลกระทบ:** C++ packed 72-byte `IpcEvent` ไม่ตรง Zig `AegisIpcEvent`; overlapped I/O ใช้ null OVERLAPPED; adapters บางตัวเป็น synthetic keepalive/stub แต่ชื่อและ readiness อาจทำให้ถูกนับเป็น real telemetry

**วิธีแก้:** quarantine legacy path หรือสร้าง schema/version translation ที่มี owner เดียว. ติดป้าย `synthetic=true`, ไม่ใช้เป็น capability evidence

**Acceptance test:** static graph ยืนยัน legacy ไม่อยู่ production path; schema fixture ตรวจ size/offset/value; synthetic event ไม่สามารถยกระดับ rule เป็น real-sensor qualification

### P2-5 — Aggregator dedup/rotation/health ไม่ exactly-once

**Path/line:** `go/aggregator/alert.go:49-85`; `go/aggregator/collector.go:70-188`; `go/aggregator/main.go:246-273`

**ผลกระทบ:** dedup ใช้ rule+src_ip+event และไม่รวม event ID/session/destination/payload; collector เริ่ม EOF, partial line/rotation อาจสูญเสีย; health counters hardcode zero. เหตุการณ์ต่างกันอาจถูก collapse หรือหายเงียบ

**วิธีแก้:** dedup ด้วย durable event identity/generation, handle rotate/truncated line, emit gaps และ health counters จาก source จริง

**Acceptance test:** same rule/IP ต่าง event ID ต้องไม่ collapse; restart/rotation/partial-line recovery ต้องไม่ duplicate/lose โดยไม่มี marker

### P2-6 — Fail-open override และ synthetic/legacy claims ต้องถูกจำกัด

**Path/line:** `src/policy/tier3_state.zig:84-95`; `src/core/rust_pep.zig:190-202,283-299`; `src/tests/integration/rust_pep_integration.zig:91-121`

**ผลกระทบ:** `AEGIS_FAIL_OPEN=1` เปิด enforcement แม้ Tier-3 ไม่ READY และทำให้ state/control semantics diverge. Rust legacy boolean block/unblock คืน false เสมอเพื่อป้องกัน bypass แต่ caller บางตัวอาจยังรายงาน intent. Tests ของ Rust เป็น negative/simulation ไม่ใช่ provider evidence

**วิธีแก้:** ตัด fail-open จาก production build หรือจำกัดด้วย signed lab profile; แยก simulation/observe/failed/host-effect statuses และลบ legacy mutation caller

**Acceptance test:** production binary ที่ env override ต้องยัง fail-closed; simulation ไม่ปรากฏเป็น enforced; legacy caller ไม่สามารถสร้าง receipt หรือแก้ host state

## 9. Dependency-aware implementation order สำหรับ milestone ถัดไป

ลำดับนี้ออกแบบให้แต่ละขั้นสร้าง prerequisite ให้ขั้นถัดไป และไม่เปิด gate ระหว่าง implementation

### Phase 0 — Freeze authority และสร้าง evidence contract lock

1. ประกาศ `prevention_gate=CLOSED` เป็น invariant ใน source/test และลบช่องทาง manual/global/env override ใน production profile. ห้ามเริ่ม valid mutation probe
2. กำหนด schema `EnforcementReceipt v1`, `ProviderQueryResult` แบบ tri-state, `RuntimeSnapshot` และ lifecycle states ใน shared contract
3. เพิ่ม static tests ที่ fail หาก block คืน `ENFORCED` ก่อน receipt+verify, unblock คืน `CLEANED` ก่อน absent query, หรือมี direct WFP mutation นอก Rust PEP
4. ทำ evidence matrix ของ 22 rules โดยแยก synthetic match, real sensor source, event ID, forensic link และ enforcement status. Synthetic-only ต้องเป็น `QUALIFIED_SYNTHETIC`

**เหตุผลด้าน dependency:** หาก schema และ invariants ยังไม่ล็อก การแก้ ABI หรือ UI จะทำให้แต่ละ layer สร้าง interpretation ของ receipt ต่างกัน

### Phase 1 — แก้ canonical/observe evidence path ก่อน host mutation

1. แก้ ETW C/Zig normalization และ compile-time size/offset fixture บน Windows
2. แก้ canonical event ID ด้วย producer generation + sequence, reject duplicate/regression และส่ง gap/loss marker
3. Preserve source/session/layer/process/node/confidence ผ่าน `pushCanonicalEventWithPayload`
4. แก้ Go monotonic clock, payload hash, IPv6 identity และ Go enum/deserializer validation
5. แก้ FIM/Registry overflow, exact attribution, buffer boundary, bounded queue และ readiness semantics
6. แก้ Nose pipe backpressure/shutdown และ run Go `-race`

**เหตุผลด้าน dependency:** receipt ต้อง link event ที่มี identity/provenance เชื่อถือได้. หาก sensor chain ยังสูญเสีย event identity การทำ receipt ต่อจะไม่สร้าง evidence ที่ตรวจสอบอิสระได้

### Phase 2 — ทำ WFP ABI และ provider ownership ให้เป็นของจริง

1. เลือก dynamic proof session หรือ persistent ownership; แนะนำ dynamic scoped proof หาก requirement ยังเป็น isolated proof
2. แยก provider/runtime/capture/proof IDs และเพิ่ม owner GUID/scope/generation
3. แก้ C driver, C bridge, Rust FFI และ Zig bindings พร้อม shared layout/offset tests
4. Implement provider-backed enumeration/read-back ที่คืน `PRESENT/ABSENT/QUERY_ERROR`, provider status, layer, conditions และ exact tuple
5. ทำ startup reconciliation/restart test และ serialize concurrent WFP operations
6. แก้ device/port ACL, authenticated broker, DLL path/signature/export validation

**เหตุผลด้าน dependency:** ต้องพิสูจน์ ABI และ provider semantics ก่อนสร้าง receipt; ไม่ควรให้ handler อาศัย query shadow state แล้วค่อยแก้ภายหลัง

### Phase 3 — ทำ policy trust และ authority binding

1. Wire signed policy loader/trust store/expiry/rollback floor เข้า daemon
2. ให้ `trusted=true` ได้จาก signed verification เท่านั้น; unsigned privileged policy ต้องไม่ reach mutation
3. ใช้ authenticated runtime capability mask, request nonce, caller identity และ receipt owner binding
4. ตัด `AEGIS_FAIL_OPEN` จาก production profile
5. แยก `pep decision`, `enforcement request`, `host effect receipt` เป็น types คนละชุด

**เหตุผลด้าน dependency:** provider ที่ถูกต้องแต่ caller/policy ไม่ authenticated ยังไม่ใช่ production authority

### Phase 4 — รวม production spine และ evidence transaction

1. เลือก daemon concrete path เป็น production spine หรือปรับ daemon ให้ใช้ `runtime_spine` จริง; ห้ามคงสองคำอธิบายที่ขัดกัน
2. ให้ `event_processor` เรียก receipt-aware enforcement transaction และ `forensic.appendReceipt` เมื่อมี confirmed receipt
3. เติม failure fate/receipt สำหรับ pipeline errors; ห้าม log แล้วหาย
4. Quarantine `nids_analyze`, legacy C++ IPC และ integration adapters ที่ไม่ใช่ runtime authority
5. ทำ end-to-end fake-provider test จาก canonical event → policy → PEP → receipt → audit/forensic → cleanup

**เหตุผลด้าน dependency:** หลัง observe path และ provider ABI เชื่อถือได้ จึงค่อยทำ transaction linkage และ remove duplicate paths

### Phase 5 — Control/UI/release hardening

1. ให้ CLI/UI/Mouth อ่าน `RuntimeSnapshot` จาก control plane เท่านั้น
2. แก้ exit codes และปิด local file/UDP mutation wrappers
3. รวม installer/deploy/release path เดียว; enforce clean tree, artifact hashes, Authenticode/catalog/signature และ fail closed
4. เพิ่ม rollback ที่ครอบคลุม service/driver/filter pre-state และ evidence ไม่ใช่เฉพาะ config
5. เพิ่ม `go test -race`, Zig targeted tests, Python tests, ABI smoke และ static gates ใน CI

### Phase 6 — Compile-only Windows gate แล้วจึง isolated host proof

1. Windows/WDK compile kernel + C bridge + Rust + Zig และ dumpbin/export checks
2. Run negative tests, ACL tests, restart/reconciliation tests และ fake provider cleanup tests
3. Run observe-only proof and capture pre-state
4. เปิด **scoped expiring proof gate** ผ่าน supervisor เท่านั้น หลังทุก prerequisite ผ่าน
5. Execute one approved exact-flow proof, require receipt/tuple/provider/benign probe/cleanup/absence evidence
6. Close gate, export linked evidence, rebuild RC and reverify hashes/signatures

**Stop conditions:** receipt incomplete, provider query unavailable, tuple mismatch, probe unexpected, cleanup uncertain, `present` remains true, signer/hash mismatch, stale owner, หรือ evidence ใดหาย ให้หยุดทันทีและคง gate closed

## 10. Commands ที่รันได้โดยไม่เปิด prevention gate

คำสั่งทั้งหมดในส่วนนี้เป็น static, compile-only, observe-only หรือ negative/fail-closed probe. **ห้ามเพิ่มคำสั่งเปิด gate, valid block, broad firewall reset หรือ IP-only cleanup ลงใน runbook**

### 10.1 Linux sandbox — static/read-only/compile checks

รันจาก `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows`

```bash
# ตรวจ provenance และไฟล์ที่เปลี่ยน โดยไม่แก้ source
git status --short
git diff --check

# ตรวจว่า gate ยังไม่มี setter ที่เปิดจาก production source
rg -n "g_prevention_gate_open|AEGIS_FAIL_OPEN|status.*ENFORCED|status.*CLEANED" \
  src rust-src drivers tools scripts

# ตรวจ direct WFP mutation ว่าอยู่ผ่าน Rust/authority path เท่านั้น
rg -n "FwpmFilterAdd|FwpmFilterDelete|BLOCK_FLOW|UNBLOCK_FLOW|aegis_pep_(enforce|unblock|query)" \
  drivers src/windows rust-src src/policy

# ตรวจ query ABI, receipt และ duplicate spine
rg -n "QUERY_FILTER|query_filter|PepFilterState|EnforcementReceipt|runtime_spine|dispatcher_phase_b|event_fabric" \
  drivers src rust-src

# ตรวจ Python syntax โดยไม่ทำ mutation
python3 -m compileall -q brain tools scripts

# ตรวจไฟล์สำคัญและ inventory แบบ read-only
find src rust-src drivers bridge nose go brain tools scripts tests -type f \
  \( -name '*.zig' -o -name '*.rs' -o -name '*.c' -o -name '*.cpp' -o -name '*.go' -o -name '*.py' \) \
  | sort > /tmp/aegis-source-inventory.txt
wc -l /tmp/aegis-source-inventory.txt

# ตรวจความพร้อมของ toolchain; absence ต้องรายงาน UNKNOWN ไม่ใช่ PASS
command -v zig || true
command -v cargo || true
command -v rustc || true
command -v go || true


### 10.2 Windows — compile, negative, observe-only และตรวจ provenance

รันบน Windows qualification host จาก `D:\NIDs_Windows` ด้วยสิทธิ์ที่จำเป็นสำหรับ **compile/read-only** ก่อน. คำสั่งเหล่านี้ไม่เปิด gate และไม่ส่ง valid mutation.

```powershell
Set-Location D:\NIDs_Windows

# Provenance และ source diff
git status --short
git diff --check
git rev-parse HEAD

# Static contract checks: ต้องเห็น gate ปิดและห้ามมี success ก่อน verify/absence
rg -n "g_prevention_gate_open|AEGIS_FAIL_OPEN|status.*ENFORCED|status.*CLEANED|present=false|POSTCONDITION_FAILED" `
  src rust-src drivers tools scripts

# Python unit/contract tests ที่ไม่ทำ host mutation
python -m pytest tests\runtime\test_operator_contracts.py -q
python -m pytest tests\runtime\test_health.py -q
python -m pytest tests\pep\test_t8_rust_pep.py -q
python tools\aegisctl.py rules validate

# Zig unit/build gate; failure หรือ missing dependency ต้องเป็น FAIL/UNKNOWN ไม่ใช่ PASS
zig build test -Doptimize=Debug

# Compile driver/native bridge/Rust artifacts. ใช้ script ของ repository และหยุดเมื่อ error
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts\wdk_build_production.ps1
cargo build --release --manifest-path rust-src\Cargo.toml

# ตรวจ export และลายเซ็นของ artifact ที่ build จาก source ชุดเดียวกัน
dumpbin /exports zig-out\bin\aegis_pep.dll
signtool verify /pa /all zig-out\bin\aegis_pep.dll
signtool verify /pa /all drivers\wfp_callout\aegis_wfp.sys

# Safe fail-closed probe เท่านั้น: invalid mutation must be rejected; no valid block
python scripts\run_control_receipt_probe.py

# Safe read-only WFP/Npcap proof เท่านั้น
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts\run_wfp_hostonly_observe_only.ps1 `
  -ExpectedKaliIp 192.168.126.10 -ListenPort 49153 -WaitSeconds 30

# Go tests/race checks for observe path; run in each Go module
Set-Location D:\NIDs_Windows\nose
go test -race ./...
Set-Location D:\NIDs_Windows\go\aggregator
go test -race ./...
Set-Location D:\NIDs_Windows
```

**ห้ามใช้เป็น production proof:** `tests\wfp\test_t11_windows_host.py` หากยังเรียก legacy `aegis_pep_unblock_ip`; ห้ามใช้ direct ctypes, IP-only cleanup, `run_controlled_proof.ps1` ที่เป็น observe-only, synthetic canary หรือ broad firewall reset เป็นหลักฐาน IPS. Valid isolated proof จะรันได้ต่อเมื่อ Phase 0–5 ผ่านและต้องมีคำสั่ง/สคริปต์ที่บันทึก complete receipt, provider read-back, benign probe, cleanup และ `present=false` ตาม sequence ใน handoff [1, §11].

## 11. สิ่งที่ยัง verify ไม่ได้จาก Linux sandbox

รายการต่อไปนี้เป็น **UNKNOWN ไม่ใช่ PASS หรือ FAIL จากการรัน host**:

| รายการ | เหตุผลที่ยังสรุปไม่ได้ | หลักฐานที่ต้องเก็บบน Windows |
|---|---|---|
| Zig/Rust/C/WDK/CMake compile และ link | sandbox ไม่มี Windows SDK/WDK และ toolchain ที่ตรง target; `build.zig` ยัง conditionally link import libraries [7] | compiler versions, full build logs, object/import library list และ clean commit |
| DLL exports และ ABI | source มี FFI names แต่ export mechanism/provenance ต้องตรวจจาก DLL จริง | `dumpbin /exports`, `sizeof/offsetof` fixture, Rust/Zig round-trip |
| WFP provider semantics | driver query ปัจจุบันเป็น shadow globals ไม่ใช่ provider enumeration | `FwpmFilterGetById0`/enum output, provider/sublayer/layer/conditions และ status |
| Filter persistence/restart | source ใช้ persistent flag + dynamic session แต่ behavior ต้องทดสอบกับ WFP engine จริง | pre-state, restart driver/service, owner reconciliation, exact ID query/cleanup |
| Host effect ของ inbound TCP/49153 | source layer เป็น ALE connect และยังไม่พิสูจน์ inbound semantics | isolated Kali probe, Windows packet/result evidence, exact tuple and no overblocking |
| Device/pipe ACL และ caller identity | ACL/token/integrity behavior เป็น OS/runtime property | standard user, low-integrity, forged PID/capability and unauthorized client negatives |
| ETW/FIM/Registry real telemetry | ABI/lifecycle และ provider GUID behavior ต้อง run บน Windows | known-value ETW fixture, lost-event counters, FIM overflow, registry exact path/value |
| Npcap attribution/restart/loss | handoff มี qualification result แต่ไม่ได้ rerun; source มี process-local IDs/backpressure gaps | Go `-race`, reconnect/restart/gap test และ live health snapshots |
| Authenticode/catalog/WDAC/service account | repository metadata ไม่ใช่ trust-chain proof | `signtool verify /pa`, catalog/driver chain, service ACL/account and install logs |
| Full 22-rule real-sensor matrix | synthetic evidence ไม่เท่ากับ real sensor; current source drops provenance in places | per-rule source event ID, pipeline correlation, forensic, receipt and final state |

ห้ามเติมช่องว่างเหล่านี้ด้วย binary ที่มีอยู่ใน workspace หรือด้วยข้อความ `RC VERIFY PASS`; verifier ที่ตรวจ SHA256SUMS/presence ไม่ยืนยันว่า artifact ถูก build จาก clean source หรือ signed/trusted [8].

## 12. Coverage ของไฟล์และรายงานย่อย

รายงานนี้ครอบคลุมข้อสรุปจาก handoff และผลย่อยทั้งห้าชุดตามข้อมูลที่ส่งมา โดยตรวจ source สำคัญซ้ำใน workspace. Coverage เชิงโมดูลสรุปดังนี้

| กลุ่มที่รายงานย่อยสำรวจ | ไฟล์/โฟลเดอร์ที่รายงานนี้นำมาประกอบ | สถานะการครอบคลุม |
|---|---|---|
| Zig policy/control/runtime | `src/control/*`, `src/policy/*`, `src/pipeline/*`, `src/daemon.zig`, `src/contract/*`, `src/forensic/*`, `build.zig` | ครอบคลุม findings หลักและตรวจซ้ำ handler, PEP, receipt, daemon, event processor, runtime state, policy loader |
| Native enforcement | `drivers/wfp_callout/*`, `drivers/minifilter/*`, `rust-src/*`, `src/windows/wfp_ioctl.c`, `bridge/*`, `mouth/*` | ครอบคลุม provider query, persistent ownership, ACL, layer, ABI, lifecycle และ legacy paths; Windows behavior ยัง unknown |
| Sensor/Nose/Go | `nose/*`, `go/aggregator/*`, `src/windows/etw_*`, `fim_*`, `registry_monitor.zig`, `src/capture/*`, `src/pipeline/telemetry_threads.zig` | ครอบคลุม ETW ABI, ID/provenance, backpressure, FIM/Registry loss, readiness และ aggregator gaps |
| Brain/control/UI | `brain/*`, `tools/aegisctl*`, `tools/aegisctl/commands/*`, `scripts/*`, `mouth/*` | findings จากผลย่อยถูกใช้และบางจุดตรวจซ้ำ; รายงานย่อย `agent_brain_control_ui.md` ไม่มีอยู่จริงใน filesystem จึงไม่อ้างว่าอ่านไฟล์นั้น |
| Integration/release | `tests/*`, `scripts/run_*`, `tools/release*`, `tools/deploy_windows.py`, installer/release/config/contracts | ครอบคลุม static-vs-live, false-green, signing, installer, rollback และ safe probe gaps |

ไฟล์ production ที่อ้างในรายงานนี้เป็น subset ที่มีผลต่อ decision โดยตรง ไม่ใช่ claim ว่าอ่านทุกบรรทัดของ inventory 270 ไฟล์. รายงานย่อย Zig ระบุ inventory 270 ไฟล์ (production/non-test 158, tests 112); ข้อสรุปจาก inventory นั้นถูกใช้เป็น coverage boundary และไม่ถูกตีความเป็น test pass. ไฟล์รายงานย่อย `agent_zig_policy.md` และ `agent_brain_control_ui.md` ไม่พบจริงใน `analysis/` ณ เวลาตรวจ จึงใช้เฉพาะ findings ที่ผลลัพธ์ย่อยส่งมาและที่ source สำคัญยืนยันได้

## 13. Definition of done สำหรับ production IPS

AEGIS จะยังไม่ควรถูกประกาศ production IPS จนกว่าจะมีหลักฐานชุดเดียวที่ trace ได้ตั้งแต่ source event ถึง cleanup ดังนี้:

1. Clean, reproducible Windows/WDK build ของ driver, C bridge, Rust PEP และ Zig พร้อม ABI size/offset/value fixtures
2. Authenticated control request ที่มี nonces, caller identity, policy hash/version, scope และ expiry
3. Provider-backed pre-state และ exact add/read-back ที่ตรง layer, direction, tuple, owner และ provider status
4. `EnforcementReceipt v1` ครบทุก field ตาม handoff และถูก serialize ผ่าน control plane, forensic และ UI โดยไม่ลดรูปเป็น decision
5. Benign isolated probe ที่พิสูจน์ผล host effect โดยไม่ overblock
6. Unblock โดยใช้ `receipt.filter_id` เท่านั้น ตามด้วย provider query เดิมที่ได้ `present=false`
7. Restart/reconciliation, ACL, unauthorized caller, replay, timeout และ cleanup uncertainty tests ผ่าน
8. Release artifacts signed/trusted, installer canonical, clean-tree provenance และ failure ทุกแบบหยุด deployment
9. 22-rule matrix แยก synthetic กับ real sensor และ link event, trace, policy, forensic, receipt, audit และ cleanup

จนกว่าจะครบ ให้รายงานสถานะเป็น **DETECTION_ONLY** หรือ **PROVIDER_READY_GATE_CLOSED** ตาม capability ที่ตรวจได้ และให้ unknown/degraded มีผลเป็น non-zero สำหรับ automation ที่ต้องการ production safety

## References

[1]: file:///home/ubuntu/upload/AEGISProductionHandoff.md "AEGIS Production Handoff"
[2]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/control/handler_registry.zig "AEGIS control handlers"
[3]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/analysis/agent_native_enforcement.md "AEGIS native enforcement code audit"
[4]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/analysis/agent_sensor_nose.md "AEGIS sensor, Nose, and Go source audit"
[5]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/analysis/agent_integration_release.md "AEGIS integration, release, and deployment audit"
[6]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/daemon.zig "AEGIS daemon startup and runtime wiring"
[7]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/build.zig "AEGIS Zig build graph"
[8]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tools/release_candidate.py "AEGIS release candidate assembler and verifier"
