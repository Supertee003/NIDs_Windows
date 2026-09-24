# AEGIS Deep Development Analysis — 2026-09-21

## Executive conclusion

AEGIS มีแกน runtime ที่ชัดเจนขึ้นแล้ว แต่ยังไม่ใช่ Production-ready IPS. `src/main.zig` เรียก `platform/win32_service.mainEntry()` และ production orchestration อยู่ใน `src/daemon.zig`; daemon มี supervisor, readiness flags, worker join และ control pipe ownership ในระดับ source. อย่างไรก็ตาม เส้นทางข้อมูลและ enforcement ยังมี contract หลายชุดที่ทำให้การพิสูจน์ end-to-end ไม่สมบูรณ์.

สถานะที่ปลอดภัยในปัจจุบันคือ **detection-only หรือ degraded mode**. ห้ามแสดง `BLOCKED_CONFIRMED` จนกว่าจะมี `EnforcementReceipt` ที่มี identity, provider/filter identity, host-effect postcondition, forensic linkage และ cleanup result ครบถ้วน.

การตรวจครั้งนี้ใช้ source จริงที่ current HEAD `46b93dc`, build graph, Git status และการอ่าน critical path. ไม่ได้แก้ source ใด ๆ เพราะ working tree มีการแก้ไขของผู้ใช้อยู่จำนวนมาก. รายการไฟล์ code ที่ tracked จาก inventory ปัจจุบันมีอย่างน้อย Zig 262 ไฟล์, Go 17 ไฟล์, Rust 8 ไฟล์, Python 143 ไฟล์, TypeScript 10 ไฟล์ และ C/C++ 24 ไฟล์.

## Repository truth และขอบเขตที่ต้องระวัง

Working tree ไม่สะอาด. มี tracked modifications ใน `build.zig`, `src/daemon.zig`, `src/contract/canonical_event.zig`, `src/capture/nose_pipe_reader.zig`, `src/policy/pep_bindings.zig`, `rust-src/lib.rs`, `nose/*`, `brain/*`, `tools/aegisctl/*`, WFP/native files และ test files. นอกจากนี้มี untracked reports, brain modules และ analysis artifacts. ดังนั้นการแก้ไขต่อไปต้องเป็น focused patch และต้องไม่ reset, checkout หรือ regenerate manifests ทับงานเดิม.

`build.zig:15-21` กำหนด `src/main.zig` เป็น executable หลัก. `build.zig:59-75` ผูก Rust PEP DLL แบบ optional และ `build.zig:78-102` ผูก native helper libraries แบบ optional. ผลคือ build graph ยอมเข้าสู่ degraded build เมื่อ artifact สำคัญหายไป ซึ่งเหมาะกับ development แต่ต้องมี production gate แยกที่ fail closed.

## Actual runtime path

เส้นทางที่ source ยืนยันได้คือ:

```text
src/main.zig
  -> platform/win32_service.mainEntry
  -> daemon.runDaemon
  -> Go Nose named pipe reader
  -> pipeline/event_queue
  -> event_processor
  -> policy evaluation
  -> Rust PEP binding
  -> forensic ring
  -> control pipe / operator API
```

`src/daemon.zig:51-85` ทำให้ `RuntimeSupervisor` เป็น owner ของ worker handles และ join reverse order. `src/daemon.zig:374-439` เริ่ม sensor, pipeline, Nose reader, ETW, FIM และ Registry. `src/daemon.zig:441-495` ใช้ readiness barrier สูงสุด 2 วินาที และแยก runtime state จาก provider readiness. ส่วนนี้สอดคล้องกับ invariant เรื่อง single runtime owner.

ข้อจำกัดคือ `src/platform/win32_pipe.zig:224-257` ยังใช้ `ConnectNamedPipe` ใน control server loop และพึ่งพา shutdown/wake path. ต้องพิสูจน์บน Windows จริงว่า wake handle ปลด blocking call ได้ทุก state. Source มี `wakeControlPipe()` ที่บรรทัด 260-270 แต่ยังไม่ใช่ host-level proof.

## Finding 1 — มี event contract อย่างน้อยสองชุด

`src/contract/event.zig:10-12` ประกาศ `IpcEvent` ขนาด 96 bytes, magic/version ชุดหนึ่ง และใช้เป็น `QueuedEvent.ev` ที่ `src/pipeline/event_queue.zig:14-20`.

ขณะเดียวกัน `src/contract/canonical_event.zig:15-17` ประกาศ CanonicalEvent อีกชุดหนึ่ง. Wire serializer ที่ `canonical_event.zig:335-390` ระบุ payload 109 bytes และ `src/capture/nose_pipe_reader.zig:6-10,48` ใช้ frame `4-byte length + 109-byte payload`.

Boundary conversion อยู่ที่ `src/pipeline/event_queue.zig:54-103`. ฟังก์ชันนี้แปลง CanonicalEvent เป็น IpcEvent โดยคัดลอก event ID, timestamp, IP, port, protocol, rule ID, payload length/hash และ flags. การมี conversion ที่ explicit เป็นแนวทางที่ถูกต้อง แต่ contract ไม่ได้มี schema identity เดียวกัน และ event field semantics ต่างกัน เช่น `EventType/PolicyAction` กับ `EventKind/EventFate/Action`.

ความเสี่ยงสูงสุดคือ `canonical_event.zig:459-469` ยังมี legacy `serialize()` และ `deserialize()` ที่ pointer-cast in-memory struct แทน explicit 109-byte encoding. เส้นทางนี้อาจใช้ natural alignment/padding ของ 128-byte Zig struct ขณะที่ Go และ named pipe ใช้ 109 bytes. ต้อง retire หรือทำให้ legacy API เรียก explicit wire codec เท่านั้น.

## Finding 2 — event identity ยังไม่ข้าม restart อย่างแท้จริง

`canonical_event.zig:283-291` ใช้ process-local atomic counter. `nose_pipe_reader.zig:255-322` ตรวจ duplicate และ non-monotonic event ID เฉพาะภายใน connection และมี comment ชัดเจนว่าการ compare ข้าม producer restart ยังทำไม่ได้. นี่ทำให้ exactly-once forensic identity ยังไม่ผ่าน production proof.

แนวทางแก้ที่ต้องเลือกให้ชัดเจนคือเพิ่ม producer ID + runtime generation + producer epoch ลง contract/extension หรือย้ายการจัดสรร global sequence มาไว้ที่ Zig ingress authority. ห้ามแก้ด้วยการ reset counter แล้วถือว่า identity ถูกต้อง.

## Finding 3 — enforcement ยังไม่สร้าง EnforcementReceipt ครบ contract

`src/policy/pep_bindings.zig:55-61` มี `PepEnforcementReceipt` แต่มีเพียง `decision`, `reason`, `quota_remaining`, `signed_by` และ `filter_id`. ยังไม่มี `request_id`, `event_id`, `trace_id`, `audit_id`, `version`, `status`, `provider`, `host_effect_confirmed` และ cleanup linkage ตาม receipt contract ใน handoff.

`src/control/handler_registry.zig:520-566` เรียก `pep.enforceFlow()` แล้วตอบ JSON เพียง `status`, `filter_id`, `reason`, `dst_ip`, `dst_port`, `protocol`. ไม่มี field ที่พิสูจน์ host postcondition และไม่มี forensic linkage. ดังนั้น response นี้ไม่ควรถูกเรียกว่า validated `EnforcementReceipt`.

`tools/aegisctl/api/control_api.py:315-321` ตรวจเพียง `status == ENFORCED` และ `filter_id != 0`. การตรวจนี้ยังไม่เพียงพอ เพราะ response สามารถมี filter ID โดยไม่มี event/request/trace/audit identity หรือ observation ว่าทราฟฟิกถูก block จริง.

`brain/enforcement_receipt.py:22-61` กำหนด validation ที่เข้มกว่าและถูกทิศทาง โดย `ENFORCED` ต้องมี `host_effect_confirmed=true`, identities positive และ forensic linkage. แต่ module นี้เป็น Python-side adapter และยังไม่ได้เชื่อมกับ handler response ที่ runtime ใช้จริง. จึงเกิด contract drift ระหว่าง runtime receipt กับ Python receipt.

## Finding 4 — Python helper มีเส้นทางที่ล้มเหลวเสมอ

`tools/aegisctl/api/control_api.py:336-355` ฟังก์ชัน `apply_firewall_block()` เรียก `request_enforcement_via_pep()` ด้วย `target_port=0` และ `rule_id=rule_name`. แต่ `request_enforcement_via_pep()` ที่บรรทัด 301-305 แปลง rule ID เป็นเลขฐานสิบ และ reject port ที่ไม่อยู่ใน 1..65535. ดังนั้น wrapper นี้จะคืน `REJECTED` เสมอสำหรับ default arguments.

ใน `brain/windows_brain.py:162-185` เส้นทาง brain ตั้งใจปิด prevention gate และคืน `FAILED` อย่างปลอดภัย. นี่เป็น fail-closed ที่ถูกต้อง แต่ documentation และ naming ยังสื่อว่าเป็น enforcement path ที่พร้อมใช้งาน. ควรแยก API ชื่อ `request_block_when_attested()` ออกจาก `alert_only_block_request()` และเพิ่ม test ที่ยืนยันว่าไม่มี caller แสดงผลเป็น confirmed block.

## Finding 5 — Rust PEP ยังเป็น provider boundary มากกว่า receipt authority

`rust-src/lib.rs:410-513` ตรวจ pointer, capability mask, policy action และเรียก WFP adapter เมื่อ decision เป็น block. ถ้า adapter คืน filter ID จะใส่ `filter_id` ใน `PepResponse`. ถ้า provider unavailable หรือ block flow ล้มเหลว จะเปลี่ยนเป็น `DECISION_ESCALATE`.

Fail-closed behavior นี้ถูกต้องในหลักการ. อย่างไรก็ตาม `PepResponse` ที่ `rust-src/lib.rs:179-186` มีเพียง decision/reason/quota/signed_by/filter_id และไม่มี host postcondition observation. `rust-src/lib.rs:314-321` เพียงรับ filter ID จาก adapter; ยังไม่มีการ verify traffic outcome, provider ownership, lifecycle generation หรือ cleanup outcome.

การตรวจ policy signature ใน `rust-src/lib.rs:22-54` ใช้ Ed25519 จริงผ่าน `ring` ซึ่งดี แต่ต้องพิสูจน์ว่าผล verification ถูกเรียกก่อน load policy ที่ runtime ใช้จริง. `src/daemon.zig:182-312` โหลด `configs/policies.json` เองและสร้าง policy ด้วย JSON parsing; จาก source ที่อ่านยังไม่มีการผูก signed canonical envelope เข้ากับ policy load path.

## Finding 6 — Go Nose path มี framing และ bounded shutdown ที่ดี แต่ metrics/identity ยังไม่ครบ

`nose/main.go:43-53` แยก capture, probe และ observe injection. `src/capture/nose_pipe_reader.zig:133-157` อ่าน short reads แบบ length-aware และ `src/capture/nose_pipe_reader.zig:207-249` ใช้ pollable NOWAIT connect/reconnect. นี่ลดความเสี่ยง shutdown hang และ partial-frame corruption.

`nose/golden_path_ffi.go:69-118` decode 109-byte wire format ด้วย offset explicit และตรวจ magic/version/struct size. แต่ comment ที่บรรทัด 300-307 ระบุว่า C++ implementation pending และ Rust implementation TBD. ดังนั้น cross-language compatibility ยังไม่ครบทุก language แม้ Go/Zig fixtures จะมีแนวทางแล้ว.

`nose_pipe_reader.zig:313-320` ตรวจ duplicate/non-monotonic ภายใน connection เท่านั้น. ต้องเพิ่ม producer generation/epoch และ test ข้าม reconnect.

## Finding 7 — policy authoring กับ runtime policy ยัง drift กันได้

TypeScript `ts_policy/src/types.ts:30-94` กำหนด action ordinals ALLOW=0, ALERT=1, BLOCK=2, QUARANTINE=3, RATE_LIMIT=4, LOG_ONLY=5. แต่ Zig runtime `src/policy/policy_ir.zig:18-26` ใช้ PASS=0, LOG=1, ALERT=2, RATE_LIMIT=3, BLOCK=4, QUARANTINE=5, ESCALATE=6. Rust `rust-src/lib.rs:198-205` ใช้ policy action ordinals อีกชุด โดย BLOCK=4.

การที่ compiler ระบุว่าตัวเอง mirror Zig policy plane ไม่พอ. ต้องมี generated contract หรือ frozen golden vectors ที่ test TypeScript, Zig และ Rust action values ใน artifact เดียวกัน. ปัจจุบันมีความเสี่ยงว่า policy จาก TS ที่ action=BLOCK จะถูก runtime อ่านเป็น action อื่น.

`ts_policy/src/compiler.ts:268-280` ยอมรับว่าการ hash ของ TS ต่างจาก Zig `std.mem.asBytes` และ cross-check ยัง deferred. นี่เป็น blocker สำหรับ signed policy digest จนกว่าจะมี canonical bytes implementation เดียว.

## Finding 8 — policy matching ยัง first-match ไม่ใช่ deterministic precedence ตาม compiler

`src/policy/policy_ir.zig:117-121` คืน policy ตัวแรกที่ match. Test ที่บรรทัด 242-275 ระบุและยืนยัน first-match behavior. แต่ `ts_policy/src/compiler.ts:8-14,245-260,348-355` อ้างลำดับ priority, specificity, rule ID และ version.

ดังนั้น compiler และ runtime decision authority ไม่ได้ใช้ rule precedence เดียวกัน. นี่เป็น policy correctness risk ที่ต้องแก้ก่อนเปิด prevention. Runtime ต้องใช้ compiled order ที่พิสูจน์แล้ว หรือ implement conflict resolver ที่ตรงกับ TS golden vectors.

## Finding 9 — health ถูกออกแบบให้ degraded อย่างถูกหลัก แต่ยังมี legacy fallback ที่ต้องแยกให้เด็ดขาด

`tools/aegisctl/api/control_api.py:575-632` ทำสิ่งถูกต้องเมื่อ daemon control pipe ใช้งานไม่ได้: คืน `runtime_available=false` และไม่ถือ PID scan เป็น operational truth. `control_api.py:635-668` แยก artifact presence จาก dependency/provider/host-effect readiness.

อย่างไรก็ตาม `control_api.py:671-732` ยังมี `compute_health_state()` แบบ legacy ที่นับ subsystem names `capture`, `etw`, `fim`, `wfp`, `pep`, `control`, ขณะที่ daemon health ใช้ worker names และ state machine names ต่างกัน. แม้ code ใหม่พยายาม override ด้วย daemon facts ที่บรรทัด 476-507 แต่ควรเลิกใช้ legacy computation ใน production decision path และเก็บไว้เป็น diagnostic-only.

`src/platform/win32_pipe.zig:17-19` ยังมี `runtimeHealthState()` ที่ต้องการ `pep_ready`, `bridge_ready`, `wfp_ready` ทั้งหมดเพื่อ RUNNING. ขณะเดียวกัน daemon ตั้งใจแยก PEP readiness จาก WFP provider readiness. ต้องมี health contract เดียว ไม่ให้ helper นี้ทำให้ UI สรุปผิด.

## Verification status

การรัน targeted Python tests ใน sandbox ทำไม่ได้เพราะ environment ไม่มี `pytest` (`/usr/bin/python3: No module named pytest`). Zig, Rust, C/C++ และ Windows host-level tests ยังไม่ได้รันใน sandbox นี้. จึงยังไม่มีหลักฐาน build/test ของ current HEAD และไม่ควรสรุปว่า source compile ได้.

Production proof ที่ยัง unavailable ได้แก่ Windows elevated preflight, real WFP provider/device open, host-effect block/unblock บน VMnet1, filter cleanup, postcondition observation, stale-filter scan, lifecycle recovery หลัง enforcement และ clean install/package/signature acceptance.

## Prioritized remediation plan

### P0 — Freeze the authority and receipt contract

สร้าง shared `EnforcementReceipt v1` ที่มีอย่างน้อย `version`, `status`, `request_id`, `event_id`, `policy_id`, `trace_id`, `audit_id`, `provider`, `filter_id`, `host_effect_confirmed`, `runtime_generation`, `cleanup_status` และ `reason`. ให้ Rust เป็นผู้สร้าง receipt, Zig handler เป็นผู้ส่งต่อแบบไม่ลด field, Python/Mouth/dashboard validate schema เดียวกัน. เพิ่ม negative tests สำหรับ missing identity, zero filter ID, provider ambiguity และ cleanup failure.

### P0 — Freeze action ordinals and canonical policy bytes

เลือก action vocabulary ชุดเดียว. สร้าง generated fixture ที่ TypeScript, Zig และ Rust อ่านร่วมกัน. เปลี่ยน TS compiler และ Zig loader ให้ hash byte stream เดียวกัน และให้ signature verification เป็น mandatory สำหรับ privileged policy. Unsigned `configs/policies.json` ต้องอยู่ใน alert-only mode เท่านั้น.

### P1 — Remove or quarantine legacy event codecs

ให้ `serialize()` และ `deserialize()` ใน `canonical_event.zig` เรียก explicit wire codec หรือ mark deprecated ที่ compile-time. เพิ่ม test ที่ยืนยันว่าไม่มี 128-byte natural-layout payload ออก named pipe. เพิ่ม conversion fixture 109-byte CanonicalEvent -> 96-byte IpcEvent พร้อมรายการ field loss ที่ตรวจได้.

### P1 — Fix cross-restart identity

เพิ่ม producer ID, runtime generation และ producer epoch ใน contract หรือสร้าง allocation service ใน Zig ingress. เพิ่ม duplicate, collision, restart and retry tests. ห้ามใช้ process-local counter เป็น global identity.

### P1 — Converge policy precedence

Implement runtime conflict resolution ให้ตรงกับ TS compiler specification และเพิ่ม golden vectors ที่มี conflicting rules. Acceptance คือทุก language ให้ winning rule เดียวกันเมื่อ input เดียวกัน.

### P2 — Complete Windows proof and release gates

หลัง lower contracts ผ่าน ให้รัน `zig build`, `zig build test`, Cargo tests, Python/TypeScript tests และ elevated PowerShell preflight บน Windows. จากนั้นทำ observe-only VMnet1 proof ก่อน host-effect proof. Host-effect proof ต้อง target disposable Windows 11 service เท่านั้น และต้องพิสูจน์ reachability ก่อน block, blocked during proof, reachability after cleanup และไม่มี stale filter.

## Immediate next session commands

บน Windows elevated PowerShell:

```powershell
Set-Location D:\NIDs_Windows
zig build
zig build test
cargo test --manifest-path Cargo.toml
python -m pytest tests\runtime\test_health.py tests\runtime\test_wire.py tests\pep\test_t8_rust_pep.py -q
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_host_production_preflight.ps1 -HealthRetries 1 -RetryDelaySeconds 1
```

หากคำสั่งใดล้มเหลว ให้เก็บ first violated postcondition, current commit, runtime generation, health before/after และ logs. ห้ามเปลี่ยน failure เป็น warning เพื่อข้าม gate.

## Final status

ระบบมี foundation ที่ดีขึ้นในด้าน single daemon owner, fail-closed intent, bounded Go-to-Zig framing และ truthful degraded health. แต่ยังมี blocker ทาง contract และ evidence ที่สำคัญกว่าการเพิ่ม feature: event schema ซ้ำ, identity ข้าม restart ไม่สมบูรณ์, receipt ไม่ครบ, policy ordinals/precedence drift และยังไม่มี Windows host-effect proof. สถานะที่ถูกต้องคือ **not production-ready; safe degraded/detection-only until evidence gates pass**.

## References

[1]: https://learn.microsoft.com/windows/win32/fwp/windows-filtering-platform-start-page "Windows Filtering Platform documentation"
[2]: https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilea "CreateFile documentation"
[3]: https://docs.vmware.com/ "VMware documentation"
