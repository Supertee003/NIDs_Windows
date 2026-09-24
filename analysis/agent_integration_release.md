# AEGIS Windows-native NIDS/IPS — Integration, Release, and Deployment Audit

**ขอบเขต:** `tests/`, `scripts/`, `configs/`, `config/`, `contracts/`, `tools/` ที่ไม่ใช่ Python, installer/deployment/release metadata และ production-path references

**Baseline ที่ตรวจเทียบ:** handoff ระบุ `46b93dc` และ prevention gate = `CLOSED` (`/home/ubuntu/upload/AEGISProductionHandoff.md:3-8`)

**ผลสรุป:** **ไม่อนุมัติ production IPS และไม่เปิด prevention gate**. Observe-only qualification มีหลักฐานที่แข็งแรง แต่ test/release/deployment layer ยังไม่สามารถพิสูจน์วงจร `valid request -> provider-backed EnforcementReceipt v1 -> exact WFP read-back -> benign host probe -> exact cleanup -> absence read-back` ได้. จุดนี้ตรงกับ blocker ใน handoff (`AEGISProductionHandoff.md:12-15, 319-338`) และเป็น **P0**.

## 1. วิธีตรวจและขอบเขตหลักฐาน

ผมอ่าน handoff ก่อนเริ่มงาน จากนั้นสร้าง inventory ด้วย `find`/`git ls-files` สำหรับ source/config/test/contract/release/deployment ในขอบเขตที่ร้องขอ โดยตัด binaries, `dist`, `build`, generated outputs, caches และ object artifacts ออกจากการตีความ. อ่านเต็มสำหรับ production-critical sources และ test/proof wrappers; ไฟล์ที่เหลือใน scope ถูก inventory และ static-scanned ด้วย `rg` เพื่อหา gate, WFP, receipt, synthetic/real evidence, rollback, signing, checksum, stale wrapper และ observability references. ไม่มีการแก้ production source.

ข้อจำกัดสำคัญคือสภาพแวดล้อมปัจจุบันเป็น Linux จึงไม่สามารถยืนยันผล Win32/WDK/Npcap/driver/service หรือรัน Windows-only host proof ได้. ดังนั้นข้อความที่ระบุว่า host enforcement ยังไม่พิสูจน์เป็นข้อสรุปจาก source/test semantics และ handoff ไม่ใช่การอ้างว่าผมรัน host proof ใหม่.

## 2. ผลตัดสินตาม production gates

| Gate | หลักฐานที่ตรวจพบ | คำตัดสิน |
|---|---|---|
| RC assembly/checksum | `tools/release_candidate.py` สร้าง `SHA256SUMS` และ verifier อ่านกลับ; `python tools/release_candidate.py --verify` ให้ `RC VERIFY PASS` สำหรับ `release/T20-final/46b93dc` | **Verified แต่เป็น self-consistency เท่านั้น** |
| Runtime/observe-only | `scripts/run_wfp_hostonly_observe_only.ps1:21-39` เรียก observe-only proof; ไม่ทำ mutation | **Verified observe-only; ไม่ใช่ IPS proof** |
| Synthetic 22-rule | Handoff รายงาน 22/22; `tests/runtime/test_golden_path.py:4-18, 166-220` ใช้ synthetic event contract และ live tests ถูก skip เมื่อไม่มี Windows/บริการ | **Synthetic/contract evidence; real rule matrix ยังไม่ครบ** |
| Rust PEP authority isolation | `tests/wfp/test_t11_wfp_enforcement.py:69-133` scan Zig source เพื่อกัน bypass | **Structural only; ไม่พิสูจน์ runtime authority** |
| EnforcementReceipt v1 | Contract มี fields บางส่วนใน `src/policy/enforcement_receipt.zig:13-47`; active block response ใน `src/control/handler_registry.zig:569-623` คืนเพียง status/filter_id/reason/tuple | **Incomplete; P0** |
| Exact provider read-back | `handler_registry.zig:510-560` เรียก `pep.queryFilter` และเทียบ tuple; handoff ระบุ query layer ยังไม่ Windows/WDK compiled และยังเป็น driver-owned state (`AEGISProductionHandoff.md:155-178`) | **In progress; ไม่ยอมรับเป็น provider-backed postcondition** |
| Cleanup/absence proof | `handler_registry.zig:626-652` ลบตาม filter ID แต่ไม่ query ซ้ำและไม่ต้องการ `present=false`; handoff ระบุยังไม่ execute (`AEGISProductionHandoff.md:330-333`) | **Missing; P0** |
| Valid mutation test | `scripts/run_control_receipt_probe.py:19-27, 51-63` ส่งแต่ invalid block และ `filter_id=0` | **Fail-closed probe only; ไม่มี valid-request coverage** |
| Release provenance | `release_candidate.py:138-158` เขียน SBOM summary/signatures metadata; `verify:207-237` ตรวจ SHA256SUMS แต่ไม่ตรวจ Authenticode, driver signature, signature value หรือ clean tree | **Partial; P1** |
| Rollback | `tools/upgrade_rollback.py:76-132, 146-206` snapshot/restore config/data paths และวัด RPO/RTO | **Config/data rollback only; ไม่ใช่ WFP filter rollback** |
| Signing/permissions | `scripts/install_drivers.bat:100-149, 160-228` เปิด test signing/self-signed fallback และดำเนินต่อเมื่อ signtool หาย; NSIS ใช้ admin แต่ไม่มี production signature gate | **Not production-complete; P1** |
| Observability/stale state | `tools/aegisctl/contracts.py:67-84` มีเพียง projection 3 labels; required receipt/postcondition/cleanup states จาก handoff ยังไม่ครบ | **Incomplete; P1** |

## 3. P0 — IPS production blocker

### P0.1 ไม่มีหลักฐาน valid block ที่ให้ EnforcementReceipt v1 ครบถ้วน

**Verified fact:** contract ระบุ `request_id`, `event_id`, `policy_id`, `decision`, `status`, `provider`, `filter_id`, `host_effect_confirmed`, `trace_id`, `audit_id`, `receipt_version` (`src/policy/enforcement_receipt.zig:13-27`). `isSuccess()` ต้องการ status `.enforced`, host confirmation, provider, filter ID, trace และ audit (`:29-33`).

แต่ active handler หลังบล็อกคืนเพียง `status`, `filter_id`, `reason`, `dst_ip`, `dst_port`, `protocol` (`src/control/handler_registry.zig:617-623`). ไม่เห็น `receipt_version`, `request_id`, `event_id`, `policy_id`, `provider`, `host_effect_confirmed`, `trace_id` หรือ `audit_id` ใน response นี้. นี่ไม่ใช่เพียง test gap; response ที่ production control plane ส่งออกไม่ตรง contract ที่ handoff กำหนด.

**Inference:** แม้ `pep.enforceFlow()` ภายในอาจสร้าง receipt ได้ แต่ handler ไม่ได้ serialize complete receipt ดังนั้น operator/evidence consumer ไม่สามารถ independently verify receipt v1 จาก control-plane output. ต้องถือว่า host effect ยังไม่ confirmed จนกว่าจะเห็น output จริงและตรวจ contract end-to-end.

### P0.2 cleanup ไม่ได้พิสูจน์ post-cleanup absence

**Verified fact:** `enforcement.unblock` รับ `filter_id` และเรียก `pep.unblockFilter` (`src/control/handler_registry.zig:626-651`) จากนั้นตอบ `{"status":"CLEANED","filter_id":...}` (`:652`) ทันที. ไม่มี query ด้วย ID เดิมหลังลบ และไม่มี `present=false` assertion. Handoff กำหนดชัดว่าต้อง query ซ้ำและหยุดหากไม่เห็น absence (`AEGISProductionHandoff.md:287-298`).

**Impact:** ไม่สามารถแยก “delete request succeeded” จาก “provider has no remaining filter” ได้. หาก filter persistent, orphaned, restart-owned หรือ delete ส่งผลเพียงบางส่วน prevention gate ต้องปิด.

### P0.3 test ที่ชื่อ WFP/IPS ยังเป็น structural หรือ legacy direct-ctypes

`tests/wfp/test_t11_wfp_enforcement.py:69-170` ตรวจการมีไฟล์, string/pattern และ manifest status. ไม่มี `WinDLL`, named pipe, driver IOCTL, provider query หรือ network probe. `tests/ips/test_t18_ips_canary_xdr.py:92-260` อ่าน source และตรวจลำดับคำ/strings ของ modules; ไม่ทำ host mutation.

ส่วน `tests/wfp/test_t11_windows_host.py:52-104` เป็น Windows-only และ skip เว้นแต่ `AEGIS_RUN_WFP_HOST_TESTS=1`, แต่เรียก `aegis_pep_unblock_ip` (`:63-69, 96-101`) และไม่ query receipt/filter ID หรือยืนยัน tuple/absence หลัง cleanup. Handoff ห้ามใช้ legacy direct ctypes proof (`AEGISProductionHandoff.md:255-258`). ดังนั้น test นี้ **ไม่ใช่ authoritative IPS proof** และควรถูกย้ายไป legacy compatibility test หรือแก้ให้เรียก control plane ตาม receipt.

### P0.4 exact read-back ยังไม่ใช่ provider-backed และไม่ได้ยืนยัน Windows/WDK build

`src/control/handler_registry.zig:542-560` เรียก `pep.queryFilter(filter_id)` และเปรียบเทียบ remote IPv4/port/protocol ได้ถูกทิศทาง. อย่างไรก็ตาม handoff ระบุ query ABI ใน `drivers/wfp_callout/aegis_wfp.{h,c}`, `src/windows/wfp_ioctl.c`, `rust-src/lib.rs`, `src/policy/pep_bindings.zig` ยังไม่ Windows/WDK compiled (`AEGISProductionHandoff.md:155-176`). Handoff ยังระบุ implementation แรกอ่าน driver-owned active state และต้องตัดสิน persistence/restart ownership ก่อน (`:176`).

**Required gate:** compile kernel driver + C bridge + Rust + Zig บน Windows/WDK; query exact provider enumeration/state by ID; prove persistent/dynamic ownership and restart behavior; only then mark postcondition as independent.

## 4. P1 — Release, deployment, signing, test-validity และ observability

### P1.1 Release verifier ตรวจ hash ของตัวเอง แต่ไม่ตรวจ provenance/signing จริง

`tools/release_candidate.py:138-158` ทำ `SBOM.json` เป็นเพียง `commit`, timestamp, artifact count และ paths. `signatures.json` มีข้อความ policy/immutable/commit/file count แต่ไม่มี signature bytes, certificate chain, signer identity หรือ verification result (`:153-158`). `verify()` ตรวจแต่ละรายการใน `SHA256SUMS` (`:207-216`) และ presence ของไฟล์บางรายการ (`:217-237`). ไม่มีการ cross-check digest กับ `build_manifest.json`, ไม่มี clean-working-tree assertion, ไม่มี signed commit/attestation, ไม่มี PE Authenticode, และไม่มี kernel driver signature/INF catalog trust.

**Verified positive:** verifier ทำงานและรายงาน `RC VERIFY PASS: .../release/T20-final/46b93dc` ใน workspace. **Caveat:** pass นี้แปลว่าไฟล์ที่ถูกบันทึกใน `SHA256SUMS` ไม่เปลี่ยนและ required paths มีอยู่ ไม่ได้แปลว่า artifact ถูก build จาก clean `46b93dc` หรือ signed/trusted.

`contracts/fixtures/release/bundle_manifest.json:1-24` ยิ่งแสดง contract ที่ยัง `signed:false`, `install_tested:false`, `rollback_tested:false`, และ `sha256:"sha256:pending"`. ถือเป็น fixture/unknown ไม่ใช่ production release evidence.

### P1.2 มี release/installer wrappers หลายรุ่นและ semantics ขัดกัน

`tools/installer.py:37-103` hard-code `AEGIS_COMMIT "2c7cb30"` และ `APPVERSION "5.0.0"`; generator ใช้ manifest เพียงสร้าง comment ต่อ component (`:106-117`) แต่ runtime `File` directives ถูก hard-code (`:53-80`). ขณะที่ checked-in `installer.nsi:5-12` เป็น version `1.0.0`, source-snapshot payload (`:22-84`) และ uninstall ลบ `$INSTDIR\config`, `$INSTDIR\drivers`, `$INSTDIR\logs` (`:111-135`). สิ่งนี้ขัดกับ generated template ที่อ้างว่ารักษา `data`, `config`, `logs`, `trust_store` (`tools/installer.py:90-101`) และขัดกับ handoff ที่กำหนด preserve data/rollback.

**Inference:** operator ที่เรียก `makensis installer.nsi` อาจได้ installer ที่ไม่ใช่ artifact/commit เดียวกับ T20 RC. ต้องเลือก canonical installer หนึ่งตัวและทำ stale wrapper fail-fast หรือเอาออกจาก release path.

### P1.3 deploy helper ไม่ deploy สิ่งที่ production path ต้องใช้ และไม่ fail closed

`tools/deploy_windows.py:44-66` copy เฉพาะ `src`, `rust-src`, `tools`, `configs`, `tests`, `kernel`, `installer`, `.github` และ top-level list. ไม่ copy `scripts`, `config`, `drivers`, `release` หรือ `runtime_manifest` โดยตรง. แต่ build/install path และ handoff ใช้ scripts/driver/release tree. `--test` เก็บ failure ไว้ใน `rc` แต่ยังเดินต่อไป install (`:141-149`); install อาจเขียนทับ return code. `install_service()` สร้าง service (`:104-125`) แต่ไม่กำหนด service account, ACL, recovery verification, binary hash หรือ start/readiness proof.

### P1.4 driver install ยอมรับ test-signing/unsigned fallback

`install_drivers.bat` ต้องการ administrator (`:77-83`) และเปิด test signing (`:100-123`). สร้าง self-signed certificate (`:127-149`), ใช้ timestamp ที่ไม่บังคับ (`:89-95`), และเมื่อ `signtool` ล้มเหลวเพียงพิมพ์ warning แล้วพยายามติดตั้งต่อ (`:160-189`). Minifilter signing ไม่มี failure gate และยังเดินต่อ (`:200-228`). Uninstall แจ้งว่า test signing ยังคงเปิด (`:243-262`).

**Production implication:** source ระบุ test-lab deployment มากกว่า signed production deployment. ยังไม่พบหลักฐาน certificate chain, EKU, catalog signature, `signtool verify /pa`, WDAC policy หรือ proof ว่า service จะ refuse unsigned/stale driver.

### P1.5 rollback เป็น config/data rollback ไม่ใช่ filter rollback และไม่ atomic ต่อ install failure

`tools/upgrade_rollback.py` มี required preservation เพียง `configs/Rules.json` (`:44-47`) และ optional trust/certs/audit/forensics (`:49-62`). มัน copy snapshot (`:76-132`) และ restore paths (`:146-206`) พร้อม RPO/RTO. ไม่เก็บ WFP pre-state, provider/filter IDs, receipt, driver/service state, binary provenance หรือ post-cleanup query.

`install_aegis.ps1:19-25` rollback ลบ install root แล้ว move backup กลับ. Upgrade ย้ายเดิมไป backup และ copy bundle (`:39-43`), แต่ไม่มี catch/atomic swap/automatic restore หาก copy หรือ driver registration ล้มเหลว. `:45-57` ตรวจเพียง driver file/service existence และพิมพ์คำสั่ง start; ไม่ start/verify driver, core health หรือ cleanup filters.

### P1.6 test matrix มี synthetic/static dominance และ false-green seams

- `tests/runtime/test_golden_path.py:4-18` ระบุ static mode รันเสมอ; live mode skip เมื่อไม่ใช่ Windows/ไม่มี components (`:228-250`). Synthetic event schema (`:166-200`) ไม่ใช่ real Npcap/ETW/FIM event.
- `tests/runtime/test_gate_e.py:1-6, 83-100` ตั้งใจทดสอบ mutation unavailable. เป็น safety proof ที่ดี แต่ไม่มี valid block/receipt test.
- `tests/runtime/test_gate_f.py:1-6, 70-105` เช่นเดียวกัน: assert unavailable และไม่เขียน local state; ไม่มี provider mutation.
- `tests/release/test_t17_perf_ci_installer.py:74-87` รัน `python -c pass` แทน Zig benchmark และตรวจ manifest strings; `:183-209` ตรวจ metadata/hash presence มากกว่าการ build artifact จาก source. มี path inconsistency ระหว่าง `src/federation/federation_bench.zig` ใน `PERF_UNITS` (`:38-44`) กับ `core/federation_bench.zig` ที่ตรวจ manifest (`:84-87`).
- `tests/policy_signing/test_t7_signed_policy.py:123-134, 209-329` สร้าง Ed25519 keypair ใหม่ใน memory ทุก test และตรวจ offline canonical JSON. ให้หลักฐาน crypto algorithm แต่ไม่ใช่ trust-store/deployment key, certificate, expiry clock, Windows file ACL หรือ signed release evidence. Docstring เองยอมรับ Zig `asBytes` กับ Python/TS JSON-canonical เป็น byte streams ที่ต่างกัน (`:48-59`), จึงต้องมี cross-language fixture ที่ artifact เดียวกันก่อน production.

### P1.7 receipt contract ถูก validate อ่อนกว่าข้อกำหนด handoff

`src/policy/enforcement_receipt.zig:41-47` ไม่บังคับ `decision == block` และไม่บังคับ `policy_id != 0`, แม้ handoff กำหนดทั้งสอง (`AEGISProductionHandoff.md:125-143`). `tools/aegisctl/contracts.py:49-64` ยอมรับ receipt version `0` (`version not in (0, RECEIPT_VERSION)`), ไม่บังคับ policy ID non-zero และไม่บังคับ decision เป็น block. ต้องทำให้ contract, Zig validator และ operator projection ใช้ exact v1 semantics เดียวกัน.

### P1.8 observability state ไม่ครบและ health wrapper สามารถสร้าง stale/false-ready signal

Handoff ต้องการ `DETECTION_ONLY`, `PROVIDER_READY_GATE_CLOSED`, `ENFORCEMENT_PROOF_ACTIVE`, `ENFORCED`, `ROLLBACK_PENDING`, `ROLLED_BACK`, `DEGRADED` และ panels สำหรับ receipt/postcondition/cleanup/provenance (`AEGISProductionHandoff.md:202-223`). แต่ `tools/aegisctl/contracts.py:67-84` project เพียง `OBSERVE_ONLY`, `ENFORCEMENT_READY`, `ENFORCEMENT_UNAVAILABLE`. ไม่มี receipt/postcondition/cleanup evidence ใน projection.

`tools/update_health_cmd.py:45-60` สร้าง default subsystem statuses เป็น ready ทั้งหมดและคำนวณ uptime จาก `now_ms - health.pid` ซึ่งไม่ใช่ process start time. หากถูกใช้กับ active CLI จะทำให้ readiness เป็น inferred/default มากกว่า daemon-owned truth. นี่ควรเป็น obsolete patch utility ที่ลบออกจาก production bundle หรือทำให้ fail เมื่อ daemon payload ไม่ใช่ authoritative.

## 5. P2 — Operational hygiene และ stale wrappers

1. `scripts/run_aegis.bat:10-16, 69-83` รองรับ `--skip-build`/`--skip-check`; phase build ยอม warning แล้วข้าม component (`:307-442`). phase start ใช้ `cmd /k` หลายหน้าต่าง (`:508-634`) และ health path ไม่ตรวจ exit code ของ `python tools/aegisctl.py health` (`:655-658`). ทำให้ launcher summary ไม่เท่ากับ runtime truth.
2. `scripts/stop_aegis.bat:10-29` ใช้ `aegis-nose.exe` ใน fallback (`:16-17`) แต่ launcher ใช้ `nose_dashboard.exe` (`run_aegis.bat:577-612`). เป็น stale-name bug; fallback อาจทิ้ง Nose ไว้. ยังมี broad image-name termination ใน launcher (`run_aegis.bat:87-96, 130-139`) และ `scripts/clean_aegis.bat` ซึ่งเสี่ยงฆ่า process อื่นที่ใช้ชื่อเดียวกัน.
3. `scripts/verify_release.ps1:16` ตั้ง `$ErrorActionPreference = 'Continue'`; checksum ตรวจเฉพาะเมื่อ `.sha256` มีอยู่ (`:42-54`), ตรวจเพียง required file/size (`:65-112`) และไม่ตรวจ artifact hashes/signatures. จึงเป็น legacy package verifier ไม่ใช่ T20 provenance gate.
4. `scripts/run_controlled_proof.ps1:22-68` เป็น `canonical_observe_only`; ใช้ `aegis-nose.exe -inject-observe` (`:37-42`) และยืนยัน `blocks == 0` (`:54-64`). ชื่อ controlled proof อาจทำให้ operator เข้าใจผิดว่าเป็น IPS proof.
5. `scripts/run_wfp_phase10_preflight.ps1:60-90` ตั้งใจ pass เมื่อ `overall_gate` เป็น false (`:85-86`) และระบุ `enforcement_attempted=false` (`:76`). ถูกต้องด้าน safety แต่ต้องตั้งชื่อ `observe-only preflight` ให้ชัดและไม่ใช้เป็น production approval.
6. `configs/runtime.json:20-27` มี `pep_enabled=true` แต่ `two_person_rule_for_block=false`; หาก production policy ต้องการ dual approval ต้องเป็น explicit deployment gate ไม่ใช่ default false.
7. `config/deployment_profile.example.json:19-25, 34-37` เปิด `replay` provider และใส่ replay ใน fallback order ขณะที่ `nose` เป็น optional (`:34-37`). หาก profile นี้ถูกนำไปใช้โดยไม่ override จะปะปน replay/synthetic source กับ real production evidence.

## 6. การแยก verified fact, inference และ unknown

### Verified facts

- Handoff prevention gate ปิด และ host mutation ไม่ได้ execute ใน qualification cycle (`AEGISProductionHandoff.md:7-8`).
- RC verifier ผ่านสำหรับ `release/T20-final/46b93dc`; verifier source ตรวจ SHA256SUMS และ required path แต่ไม่ตรวจ signing.
- Observe-only wrapper ไม่ส่ง valid mutation; control receipt probe ส่ง invalid mutation เท่านั้น.
- Host WFP test ถูก skip นอก Windows/เมื่อ env flag ไม่ตั้ง และใช้ legacy IP-based unblock.
- Active `enforcement.verify` มี exact tuple comparison ใน handler แต่ block/unblock responses ไม่ใช่ complete receipt + cleanup absence proof.
- Config/data rollback tool มี RPO/RTO fields แต่ไม่มี WFP filter state.
- Driver installer ใช้ test signing/self-signed fallback และ warning-based continuation.

### Inferences

- Production operator surface อาจแสดง “enforced” ได้ยากขึ้นเมื่อใช้ `tools/aegisctl/contracts.py` เพราะ projection กัน receipt ไม่ครบ แต่มีโอกาสที่ stale wrappers/other dashboards ยังรายงานจาก policy/provider readiness. ต้องตรวจ live dashboard บน Windows.
- Installer path ที่ถูกเรียกจริงขึ้นกับ operator/CI entrypoint; มีอย่างน้อย `installer.nsi`, `installer/aegis.nsi`, `tools/installer.py`, `scripts/install_aegis.ps1`, `tools/deploy_windows.py` ที่ semantics ไม่ตรงกัน จึงมี provenance drift risk สูง.
- Persistent WFP filter ที่ identity อยู่ใน globals อาจ orphan หรือไม่สามารถ query ต่อหลัง driver restart; ต้องพิสูจน์บน host ก่อนสรุป behavior.

### Unknowns ที่ห้ามเดา

- ยังไม่ทราบว่า query ABI compile ผ่าน WDK/Windows หรือ provider enumeration ตรงกับ driver-owned state หรือไม่.
- ยังไม่ทราบว่า `pep.enforceFlow()` ภายในสร้าง receipt ครบทุก field หรือไม่ เพราะ active handler ไม่ serialize ให้เห็น.
- ยังไม่ทราบว่า production binaries ใน RC สร้างจาก clean commit `46b93dc` หรือ working tree ที่มีการเปลี่ยนแปลง.
- ยังไม่ทราบ certificate chain, Authenticode/catalog verification, service ACL/SDDL และ actual Windows service account.
- ยังไม่ทราบว่า installed driver/filter pre-state และ post-cleanup state เป็นอย่างไรใน host จริง.

## 7. Exact proof sequence ที่ต้องใช้ก่อนเปิด gate

ใช้ sequence นี้เท่านั้นกับ isolated scope ที่ handoff อนุมัติ: Kali `192.168.126.10`, Windows `192.168.126.1`, TCP destination `49153`, policy `0xE901`, lowest proof severity (`AEGISProductionHandoff.md:145-153`). ห้ามใช้ IP-only cleanup หรือ broad firewall reset.

1. หยุด stale AEGIS wrappers/processes แบบ PID/service-owned และยืนยันไม่มี duplicate owner.
2. Start เฉพาะ RC ที่ verified; บันทึก RC path, commit, executable/DLL hashes และ signer.
3. Capture health: runtime `RUNNING`, `degraded=false`, Nose/FIM/ETW/Registry ready และ prevention gate closed.
4. Capture WFP provider/filter **pre-state** และ service/driver state.
5. Prepare proof scope, rollback snapshot, audit ID, trace ID และ event ID.
6. Open an expiring proof gate; log who/when/scope/expiry.
7. ส่ง exact-flow block ผ่าน named control pipe -> Zig handler -> Rust PEP เท่านั้น.
8. Require complete `EnforcementReceipt v1`: version=1; non-zero request/event/policy/trace/audit; decision=block; status=enforced; provider non-empty; filter ID non-zero; host confirmation=true.
9. Query exact `receipt.filter_id` ผ่าน provider-backed path และ compare destination IP, port, protocol; reject driver-owned-only state until independently validated.
10. ส่ง benign Kali probe และ verify expected host postcondition with source/destination/port/protocol evidence.
11. Unblock using **only** `receipt.filter_id`.
12. Query same ID again and require `present=false`; record provider status and absence response.
13. Close gate and verify no stale `ENFORCED`; state must become `ROLLED_BACK` or `DEGRADED` according to evidence.
14. Export linked event, forensic, audit, receipt, trace, pre/post filter evidence, runtime health, RC provenance and final hashes.

**Stop conditions:** receipt incomplete; query not provider-backed; tuple mismatch; benign probe unexpected; cleanup error; `present` remains true; stale owner exists; signer/hash mismatch; any required evidence missing. Stop immediately and do not compensate with IP-only removal.

## 8. เครดิตต่ำ: testable next steps

1. **Static contract lock (no host mutation):** add tests asserting the active block response serializes every required receipt v1 field and that `decision=block`, `policy_id!=0`, `receipt_version=1` are mandatory. Add a negative test for `host_effect_confirmed=true` without provider query.
2. **Cleanup contract lock:** add a fake provider adapter test that returns present after delete; require `CLEANUP_FAILED` and no `ROLLED_BACK` response. Add success case requiring post-delete `present=false`.
3. **Replace legacy Windows test:** rewrite `tests/wfp/test_t11_windows_host.py` to call `tools/aegisctl.py` named pipe, persist receipt JSON, call `enforcement.verify`, then unblock by receipt ID and verify absence. Mark old ctypes test legacy and prohibit it in release CI.
4. **Compile-only ABI gate on Windows:** run the handoff test bundle plus `scripts/wdk_build_production.ps1`; fail if any one of kernel/C/Rust/Zig query ABI units is not compiled. Do not execute mutation yet.
5. **Release provenance gate:** make `release_candidate.py` fail when `git diff --quiet HEAD` is false, include per-file digest and source commit in SBOM, verify `build_manifest.json`, and require `signtool verify /pa` plus driver catalog verification. Make missing signature fail, not warn.
6. **Unify installers:** choose `tools/installer.py` or `installer/aegis.nsi` as canonical; generate a checked-in artifact from the exact RC and delete/rename conflicting v1.0/source-snapshot wrapper. Add an install/uninstall smoke test that proves `data`, trust, audit and forensic paths survive.
7. **Fix stale wrappers:** correct Nose process name, remove broad image-name kill fallback, require PID ownership, check every build/health exit code, and remove `update_health_cmd.py` from production path.
8. **Evidence matrix:** for each 22 rules record `synthetic_match`, `real_sensor_source`, source event ID, canonical event, forensic link, observe-only path, enforcement status, and final qualification state. Synthetic-only remains `QUALIFIED_SYNTHETIC`.

## 9. Files reviewed / inventory anchors

The scope inventory covered all source/config/test/release/deployment files under `tests/`, `scripts/`, `configs/`, `config/`, `contracts/`, `tools/`, `release/`, `installer/`, `deployment/`, plus `installer.nsi`, excluding binaries/generated/cache outputs. High-value files read in full include:

- **Contracts/control:** `src/policy/enforcement_receipt.zig`, `src/control/handler_registry.zig`, `tools/aegisctl/contracts.py`, `tools/aegisctl/api/control_api.py`.
- **WFP/IPS tests:** `tests/wfp/test_t11_wfp_enforcement.py`, `tests/wfp/test_t11_windows_host.py`, `tests/ips/test_t18_ips_canary_xdr.py`, `tests/pep/test_t8_rust_pep.py`.
- **Runtime/release tests:** `tests/runtime/test_gate_e.py`, `tests/runtime/test_gate_f.py`, `tests/runtime/test_health.py`, `tests/runtime/test_golden_path.py`, `tests/release/test_t17_perf_ci_installer.py`, `tests/policy_signing/test_t7_signed_policy.py`.
- **Proof/deployment:** `scripts/run_control_receipt_probe.py`, `scripts/run_wfp_hostonly_observe_only.ps1`, `scripts/run_controlled_proof.ps1`, `scripts/run_wfp_phase10_preflight.ps1`, `scripts/run_aegis.bat`, `scripts/stop_aegis.bat`, `scripts/install_aegis.ps1`, `scripts/install_drivers.bat`, `scripts/verify_release.ps1`.
- **Release/rollback:** `tools/release_candidate.py`, `tools/upgrade_rollback.py`, `tools/create_manifest.py`, `tools/installer.py`, `tools/deploy_windows.py`, `release/T20-final/46b93dc/{SBOM.json,SHA256SUMS,signatures.json,KNOWN_LIMITATIONS.md,ROLLBACK.md}`, `contracts/fixtures/release/bundle_manifest.json`.
- **Production path/config:** `analysis/PRODUCTION_PATH.md`, `docs/runbooks/RB-005-config-rollback.md`, `configs/runtime.json`, `config/deployment_profile.example.json`, release manifest under `release/aegis-nids-windows-6.0.0-20260916_223148/`.

## References

[1]: file:///home/ubuntu/upload/AEGISProductionHandoff.md "AEGIS Production Handoff"
[2]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/analysis/PRODUCTION_PATH.md "AEGIS Production Path"
[3]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/policy/enforcement_receipt.zig "AEGIS EnforcementReceipt v1 contract"
[4]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/control/handler_registry.zig "AEGIS control handlers"
[5]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/wfp/test_t11_windows_host.py "AEGIS Windows WFP host test contract"
[6]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tools/release_candidate.py "AEGIS RC assembler/verifier"
[7]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tools/upgrade_rollback.py "AEGIS config/data rollback tool"
[8]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/scripts/install_drivers.bat "AEGIS Windows driver installation wrapper"
[9]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tools/installer.py "AEGIS installer generator"
[10]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/installer.nsi "AEGIS checked-in NSIS installer"
[11]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/release/test_t17_perf_ci_installer.py "AEGIS release/install contract tests"
[12]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/scripts/run_control_receipt_probe.py "AEGIS safe control receipt probe"
[13]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/scripts/run_wfp_hostonly_observe_only.ps1 "AEGIS WFP observe-only proof wrapper"
[14]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/contracts/fixtures/release/bundle_manifest.json "AEGIS release contract fixture"
[15]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/docs/runbooks/RB-005-config-rollback.md "AEGIS config rollback runbook"

**Final recommendation:** retain `prevention_gate = CLOSED`. The next milestone is not opening the gate; it is one Windows/WDK-compiled, isolated, reversible block-and-rollback proof producing a complete receipt and independently verified provider postconditions.
