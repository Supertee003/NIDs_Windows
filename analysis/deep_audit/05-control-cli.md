# Deep Audit 05 — Python Control API, CLI, Dashboard และ Operational Tools

## ขอบเขตและข้อสรุป

รายงานนี้ตรวจ source ที่ติดตามด้วย Git จริงใน repository `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows` โดยจำกัดขอบเขตไว้ที่ Python control API, `aegisctl` CLI, dashboard และเครื่องมือ control, health, forensic, lifecycle, network, policy และ backup ตามที่กำหนด การตรวจไม่ใช้ `netsh`, Windows Firewall API, legacy `block_ip` หรือไฟล์ bookkeeping เป็นหลักฐานว่าเกิด host enforcement จริง และไม่ได้รัน controlled host block หรือเปลี่ยนระบบภายนอก

**ผลสรุปคือยังไม่ควรถือว่า production-ready** โค้ดมีเส้นทางที่ตั้งใจให้ Python ส่งคำสั่งไปยัง Zig daemon และให้ Rust PEP เป็นผู้มีอำนาจ enforcement แต่ contract ด้าน authorization, freshness, replay protection และ receipt ยังไม่ถูกส่งผ่านจาก Python อย่างครบถ้วน เส้นทาง retry ใช้กับคำสั่งที่มี side effect ได้ จึงเสี่ยงทำ enforcement ซ้ำเมื่อ response สูญหาย นอกจากนี้ helper enforcement ที่เปิดเผยอยู่ตรวจไม่ผ่าน input ที่ wrapper ส่งเองเสมอ มี compatibility modules ที่แก้ไฟล์ bookkeeping หรือพิมพ์ว่าสำเร็จโดยไม่ยืนยัน daemon postcondition และ dashboard มีทั้ง health false-positive กับโค้ดที่ import หรือเชื่อมต่อไม่ได้

## Inventory และไฟล์ที่ตรวจจริง

### Implementation, configuration และ protocol

ไฟล์ implementation ที่ตรวจครบใน scope ได้แก่ `tools/aegisctl.py`, `tools/aegisctl/__init__.py`, `tools/aegisctl/api/__init__.py`, `tools/aegisctl/api/control_api.py`, `tools/aegisctl/client.py`, `tools/aegisctl/config.py`, `tools/aegisctl/utils.py`, `tools/aegisctl/commands/__init__.py`, `tools/aegisctl/commands/alerts.py`, `tools/aegisctl/commands/api.py`, `tools/aegisctl/commands/backup.py`, `tools/aegisctl/commands/canary.py`, `tools/aegisctl/commands/console.py`, `tools/aegisctl/commands/dashboard.py`, `tools/aegisctl/commands/events.py`, `tools/aegisctl/commands/forensic.py`, `tools/aegisctl/commands/intelligence.py`, `tools/aegisctl/commands/lifecycle.py`, `tools/aegisctl/commands/logs.py`, `tools/aegisctl/commands/network.py`, `tools/aegisctl/commands/policy.py`, `tools/aegisctl/commands/rules.py`, `tools/aegisctl/commands/simulate.py`, `tools/aegisctl/commands/status.py`, `tools/aegisctl/web_dashboard/app.py`, `aegis_dashboard/Cargo.toml`, `aegis_dashboard/Cargo.lock` และ `aegis_dashboard/src/main.rs`

Root operational tools ที่เกี่ยวข้องและตรวจแล้วคือ `tools/backup_recovery.py`, `tools/ci_coverage.py`, `tools/config_validator.py`, `tools/create_manifest.py`, `tools/deploy_windows.py`, `tools/final_audit.py`, `tools/final_regression.py`, `tools/generate_truth_artifacts.py`, `tools/golden_path_evidence.py`, `tools/inspect_pe_exports.py`, `tools/installer.py`, `tools/probe_control_pipe.py`, `tools/release_candidate.py`, `tools/release_engineering.py`, `tools/truth.py`, `tools/update_health_cmd.py`, `tools/upgrade_rollback.py` และ compatibility path `tools/legacy/backup_recovery.py`

ไฟล์ config, contract และ operational documentation ที่ใช้เทียบพฤติกรรมคือ `config/Rules.json`, `configs/Rules.json`, `configs/runtime.json`, `configs/schema.json`, `shared/protocol/control_protocol.md`, `docs/runtime/COMPONENT_MATRIX.md`, `docs/runbooks/RB-002-forensic-query.md` และ `docs/runbooks/RB-006-subsystem-health-check.md`

หลักฐานทดสอบที่ตรวจคือ `tests/runtime/test_aegisctl.py`, `tests/runtime/test_gate_d.py`, `tests/runtime/test_health.py`, `tests/runtime/test_restart.py`, `tests/runtime/test_timeouts.py`, `tests/runtime/test_wire.py`, `tests/runtime/test_component_matrix.py`, `tests/runtime/test_states.py`, `tests/runtime/test_golden_path.py`, `tests/runtime/test_harness_integration.py`, `tests/forensics/test_t12_forensics_replay.py`, `tests/policy_signing/test_t7_signed_policy.py` และ `tests/cython/test_cython_no_policy_path.py`

ไม่พบใน scope ที่ตรวจเป็นรูปธรรม ได้แก่ test เฉพาะสำหรับ Windows named-pipe ACL และ impersonation, test สำหรับ authorization/freshness/replay ของ control protocol, test สำหรับ TCP compatibility path, test สำหรับ enforcement receipt end-to-end, test สำหรับ dashboard Flask/Rust routes และ test สำหรับ archive traversal หรือ process identity ของ lifecycle commands ทั้งนี้มีชื่อคำสั่ง `snapshot` ที่ Rust dashboard เรียก แต่ไม่พบ parser หรือ `cmd_snapshot` ใน `tools/aegisctl.py`

## Architecture และ call/data/control flow

### เส้นทาง CLI และ Python control API

เมื่อเรียก `python tools/aegisctl.py ...` entrypoint สร้าง parser และ dispatch ด้วยชื่อ `cmd_<command>` ในไฟล์ root ที่บรรทัด 939–952 ของ `tools/aegisctl.py` เส้นทางนี้ไม่ได้ import และไม่ได้ลงทะเบียน `setup_subcommands()` จาก package command modules แบบศูนย์กลาง แต่มี implementation ซ้ำกันใน root และใน `tools/aegisctl/commands/*` ดังนั้นคำสั่งที่ชื่อเดียวกันอาจมี semantics ต่างกันตาม entrypoint ที่เรียก

คำสั่งอ่านสถานะหรือ health ใน root เรียก `get_health_payload()` และ `get_all_status()` จาก `tools/aegisctl/api/control_api.py` ซึ่งพยายาม query daemon ก่อน แล้วจึงใช้ PID/process inspection เป็นข้อมูลวินิจฉัยเท่านั้นเมื่อ daemon ไม่ตอบกลับ `get_health_payload()` ตั้งใจไม่ยกระดับ PID เก่าให้เป็น runtime truth ที่บรรทัด 575–580 ถือเป็นทิศทางที่ถูกต้อง แต่ `compute_health_state()` ยังใช้รายการ subsystem รุ่นเก่าที่บรรทัด 689–732 และมีการนับ readiness เทียบกับชื่อคงที่หกชื่อ จึงอาจสร้างผล health ที่ขัดกับ canonical names ของ daemon

เส้นทาง enforcement ที่ตั้งใจคือ Python ตรวจ `IPv4Address`, policy id, destination port และ protocol ที่ `control_api.py:279–321` จากนั้นส่ง `enforcement.block` ไป control daemon ผ่าน named pipe และคาดหวัง receipt ที่มี `status` และ `filter_id` อย่างน้อย จากสถาปัตยกรรมที่ระบุใน `shared/protocol/control_protocol.md:8–19,40–55` ขอบเขต privilege ควรเป็น Python user/control client → Zig daemon/control handler → Rust PEP → WFP kernel boundary อย่างไรก็ตาม source ใน scope นี้ยืนยันได้เพียงการส่ง request และตรวจ field บางส่วน ไม่ใช่ host-effect proof

### Transport และ process/language boundary

contract ระบุ named pipe `\\.\pipe\aegis_control`, JSON หนึ่ง request ต่อหนึ่ง connection และ response `{ok,data,error}` ที่ `shared/protocol/control_protocol.md:14–37` ฟังก์ชัน `_query_daemon()` ใน `control_api.py:70–130` ใช้ Win32 `CreateFileW`, `WriteFile`, `ReadFile` และปิด handle เมื่อการอ่านจบ ส่วน `AegisClient` ใน `tools/aegisctl/client.py:88–106` ใช้ `pywin32` เป็น implementation ซ้ำอีกชุด

`AegisClient` ยังมี `transport="tcp"` ที่ `client.py:65–77,108–122` แม้ protocol frozen ระบุว่า named pipe เป็น transport เดียวที่บรรทัด 91 การเลือก transport ไม่ได้ถูกผูกกับ privilege boundary หรือ caller identity; request ที่ส่งทั้ง pipe และ TCP มีเพียง `command` กับ `payload` การสร้าง `request_id`, `nonce` และ `role` ใน `tools/aegisctl/utils.py:161–192` เป็นเพียงการเขียน audit file ก่อนส่ง เพราะ `client.send(command, kwargs)` ไม่ได้ส่ง envelope เหล่านั้นไป daemon

### Dashboard และ operational tools

Flask dashboard ใน `tools/aegisctl/web_dashboard/app.py` เรียก `get_all_status()`, `get_defcon()` และ `load_rules()` แล้วเก็บ cache ทุกสองวินาที (`app.py:47–83`) จากนั้นเปิด `/health`, `/rules`, `/api/status`, `/dashboard` และ `/health/check` โดยไม่มี authentication/authorization middleware และ main ใช้ `app.run(host="0.0.0.0", ...)` ที่บรรทัด 347–356

Rust egui dashboard ใน `aegis_dashboard/src/main.rs` อ่าน `logs/aegis_core.ndjson` และ `configs/Rules.json` โดยตรง และพยายามเรียก `python tools/aegisctl.py snapshot` ที่บรรทัด 115–129 เพื่อเอา runtime snapshot นี่เป็น boundary ข้ามภาษาและ subprocess ที่เกิดจาก GUI thread เดียวกับ refresh loop ไม่ใช่ named-pipe client โดยตรง

Operational tools แบ่งเป็นเส้นทางที่สร้าง snapshot/restore จริงใน `tools/backup_recovery.py` และ `tools/upgrade_rollback.py` กับ compatibility command modules ที่แก้ไฟล์ใต้ `logs/` หรือ `config/` โดยตรง เช่น `tools/aegisctl/commands/network.py`, `policy.py` และ `tools/aegisctl.py` เอง การแก้ไฟล์เหล่านี้ไม่ใช่หลักฐานว่า Rust PEP หรือ WFP เปลี่ยน host state

## Critical findings

### C-01 — Authorization envelope และ protocol security fields ไม่ได้เดินทางไป daemon และมี TCP path ที่ขัดกับ contract

**หลักฐาน:** `shared/protocol/control_protocol.md:56–95` กำหนด ACL แบบ strictly ordered, request freshness, replay protection ด้วย `(request_id, nonce)` และ named pipe เป็น transport เดียว ขณะที่ `tools/aegisctl/utils.py:170–190` สร้าง `role`, `request_id`, `nonce` ไว้ใน `envelope` แล้วบันทึกลง `logs/control_audit.ndjson` แต่ส่งจริงเป็น `client.send(command, kwargs)` ซึ่งสร้าง JSON เพียง `{"command":...,"payload":...}` ที่ `tools/aegisctl/client.py:100–104` และ `:110–112` นอกจากนี้ `AegisClient` อนุญาต `transport="tcp"` ที่ `client.py:65–77,108–122`

ผลคือ audit log อาจบอกว่ามี role และ nonce แต่ daemon ไม่ได้รับค่าที่ใช้ตรวจสิทธิ์ ความสดใหม่ หรือ replay และผู้เรียกสามารถเลือก TCP compatibility path ที่ protocol ประกาศห้ามได้ หาก daemon เปิด port 5117 ตามค่า default ใน `tools/aegisctl/config.py:6–10` จะเกิด control boundary ที่ไม่ตรงกับ ACL/transport contract ความรุนแรงเป็น critical เพราะเกี่ยวข้องกับคำสั่ง privileged โดยตรง ไม่ใช่เพียงรูปแบบ log

**การแก้ที่จำเป็น:** ตัด TCP ออกจาก production client หรือทำให้เป็น explicit test-only build ที่ daemon ปิดรับใน production; นิยาม request envelope เดียวใน Python และส่ง `version/magic/request_id/caller_id_hash/role/issued_at_ms/timeout_ms/nonce` ผ่าน named pipe ทุกครั้ง; ให้ daemon ตรวจ ACL, freshness และ single-use replay atomically ก่อน dispatch; ห้ามเขียน audit decision เป็น success/attempt จนกว่าจะได้รับ decision จาก daemon

### C-02 — Retry ครอบคลุมคำสั่งที่มี side effect และไม่มี idempotency/receipt correlation

**หลักฐาน:** `_query_daemon_retry()` ระบุ docstring ว่าใช้กับ read-only query ที่ `tools/aegisctl/api/control_api.py:144–152` แต่ `request_enforcement_via_pep()` เรียก `_query_daemon_retry("enforcement.block", ...)` ที่ `control_api.py:315` และ `cleanup_enforcement_filter()` เรียกแบบเดียวกับ `enforcement.unblock` ที่ `:328–330` การ retry เกิดสามครั้ง โดยพัก 50 ms เมื่อผลลัพธ์เป็น `None` การที่ response หายหลัง daemon ทำ host effect แล้วจะทำให้ request เดิมถูกส่งซ้ำ และไม่มี request id ที่ daemon รับไปใช้ deduplicate ตาม C-01

นี่อาจสร้าง filter มากกว่าหนึ่งตัวสำหรับ block เดียว หรือ cleanup ผิดตัวเมื่อการตอบกลับไม่แน่นอน อีกทั้ง receipt ที่คืนจากรอบแรกไม่ได้ถูกนำไป correlate กับรอบถัดไป ความรุนแรงเป็น critical เพราะเป็น reliability/security property ของ privileged operation

**การแก้ที่จำเป็น:** แยก `query_with_retry()` สำหรับ read-only ออกจาก `send_mutation_once()`; mutation ต้องมี request id ที่ daemon deduplicate และตอบสถานะเดิมอย่าง idempotent; หาก timeout หลังส่ง mutation ให้ query ด้วย request id เพื่อ resolve outcome ก่อน retry ไม่ใช่ยิงคำสั่งใหม่; เพิ่ม test ด้วย fault injection ระหว่าง host effect กับ response

### C-03 — Enforcement helper ที่ public อยู่ตรวจไม่ผ่าน input ที่ wrapper ส่งเอง และ receipt validation ยังไม่ใช่ schema validation

**หลักฐาน:** `control_api.py:301–306` บังคับ `target_port` อยู่ในช่วง 1–65535 และ `rule_id` ต้องแปลงเป็นเลขฐานสิบ แต่ `apply_firewall_block()` ที่ `:345–351` ส่ง `target_port=0` และค่า default `rule_name="AEGIS"` ซึ่งไม่ใช่ numeric policy id ดังนั้น helper นี้คืน `REJECTED`/`FAILED` แม้ IP ถูกต้อง และไม่สามารถเป็น path สำเร็จได้ตาม source ปัจจุบัน

แม้ route จะได้ response กลับมา โค้ดตรวจเพียง `status == "ENFORCED"` และ `filter_id != 0` ที่ `control_api.py:316–321` ไม่ตรวจ request id, trace id, audit id, policy id, event id, runtime generation, protocol version, target tuple หรือ cleanup metadata ตาม receipt linkage ที่ระบบต้องการ การ serialize receipt เป็น string ให้ caller ไม่ได้ทำให้ receipt ถูก link เข้า forensic evidence

**การแก้ที่จำเป็น:** กำหนด request/receipt schema เป็น typed model และตรวจทุก field ที่จำเป็น รวมถึง binding ระหว่าง receipt กับ request; แก้ API contract ให้ wrapper รับ port/policy ที่ถูกต้องหรือยกเลิก wrapper ที่รับค่าไม่ครบ; หลัง `ENFORCED` ต้อง query/ตรวจ postcondition และบันทึก receipt เดียวกันเข้า audit/forensic chain; เพิ่ม negative tests สำหรับ port 0, nonnumeric policy, mismatched target และ receipt ที่ขาด field

### C-04 — Web dashboard เปิด network exposure โดยไม่มี auth และ health endpoint ยืนยัน RUNNING แบบไม่อิง daemon

**หลักฐาน:** `tools/aegisctl/web_dashboard/app.py:39–40` ตั้ง secret แบบ hard-coded แต่ไม่ใช้เป็น authentication; route ที่ `:110–172` ไม่มี authorization; main เปิด `0.0.0.0` ที่ `:347–356`; `/rules` คืน rules ทั้งชุด และ `/api/status` คืน cache ให้ external consumer ที่ `:132–156` การเปิดทุก interface ทำให้ข้อมูล subsystem, PID, DEFCON และ policy ออกนอกเครื่องได้โดยไม่ตรวจ caller

ยิ่งไปกว่านั้น `health()` คืน `{"state":"RUNNING"}` ที่ `app.py:117–129` แม้ cache จะว่างหรือ daemon ล่ม และ branch `if data is None: jsonify(...), 503` ไม่มี `return` ที่ `:115–117` จึงไม่หยุดการตอบ fabricated health ผลนี้ทำให้ load balancer หรือ operator เห็น healthy ทั้งที่ control plane ใช้งานไม่ได้ ความรุนแรงเป็น critical เพราะเป็นทั้ง exposure และ operational health false-positive

**การแก้ที่จำเป็น:** bind loopback เป็นค่า defaultและแยก explicit secure reverse-proxy mode; เพิ่ม authentication, authorization และ CSRF policy แม้ dashboard จะ read-only; ให้ `/health` คืนข้อมูลจาก `get_health_payload()` พร้อม `runtime_available` และคืน 503 เมื่อ daemon ไม่พร้อม; ลบ hard-coded secret และเพิ่ม tests สำหรับ unauthenticated request, stale cache และ daemon unavailable

### C-05 — Restore archive เขียน path จาก manifest โดยไม่จำกัด root

**หลักฐาน:** `tools/backup_recovery.py:75–121` อ่าน `entry["path"]` จาก `__manifest__.json`, สร้าง `Path(entry["path"])` และ `path.open("wb")` โดยไม่มีการบังคับว่า path ต้องอยู่ใต้ repository/data root ไม่มีการ reject absolute path หรือ `..` traversal หาก administrator restore archive ที่ crafted จะเขียนไฟล์นอก repository ด้วยสิทธิ์ของผู้รันเครื่องมือ

`tools/legacy/backup_recovery.py` เป็น compatibility implementation ที่ต้องถูกตรวจและปิดพร้อมกัน ไม่ควรแก้เพียง modern path แล้วปล่อย legacy path ให้มี policy ต่างกัน ความรุนแรงเป็น critical เพราะเป็น arbitrary file write ใน administrative operation

**การแก้ที่จำเป็น:** ใช้ allowlist ของ relative paths ที่ backup สร้างได้; resolve path แล้วตรวจ `commonpath` กับ destination root ก่อนเปิดไฟล์; reject absolute path, symlink และ duplicate entries; verify manifest signature/integrity ก่อน extraction; restore ลง staging directory แล้ว atomically promote หลังตรวจครบ; เพิ่ม test สำหรับ `../../`, drive-letter path, symlink และ duplicate manifest entry

### C-06 — Compatibility command modules แก้ bookkeeping หรือพิมพ์ success โดยไม่พิสูจน์ control-plane postcondition

**หลักฐาน:** `tools/aegisctl/commands/network.py:13–132` แก้ `blocked_ips.json`/`quarantine.json` โดยตรง และ `:145–190` แก้ `pep_state.json` หรือเขียน Rules จากไฟล์ policy; `tools/aegisctl/commands/policy.py:37–66` แก้ `disabled_rules.json` แล้วรายงาน ENABLED/DISABLED โดยไม่ส่ง request ไป daemon; `tools/aegisctl/commands/backup.py:7–14` พิมพ์ `[OK] Backup created` และ `[OK] Restore complete` โดยไม่อ่านหรือเขียน archive เลย

root entrypoint มี fail-closed บางส่วน เช่น `tools/aegisctl.py:682–721,724–743` คืน `_unavailable()` สำหรับ mutation ที่ไม่ได้ต่อ PEP แต่การมี duplicate modules ที่ semantics ตรงข้ามกันทำให้ผู้ใช้หรือสคริปต์ที่ import module ผิดชุดสามารถได้ผลลัพธ์ลวงได้ โดยเฉพาะ `network.py:169–190` เรียก `control_request()` แล้วไม่ตรวจ response ก่อนเขียน policy และพิมพ์ success

นี่เป็น critical operational correctness: bookkeeping ไม่ใช่ enforcement evidence และ no-op backup อาจทำให้ operator เชื่อว่ามี recovery point ทั้งที่ไม่มีไฟล์ การแก้ต้องเหลือ implementation เดียวที่ root dispatch ใช้ร่วมกัน ทุก mutation ต้องคืน structured result จาก daemon, ตรวจ receipt/postcondition และใช้ exit code ที่สอดคล้อง; ลบหรือ quarantine compatibility modules และทำให้ `backup`/`restore` fail-closed หากยังไม่มี implementation

### C-07 — Named pipe มีเส้นทาง hang และ handle leak ที่ทำให้ control/health ไม่ reliable

**หลักฐาน:** `tools/aegisctl/client.py:88–106` เรียก `CreateFile`, `WriteFile`, `ReadFile` แล้ว `CloseHandle` ที่บรรทัด 103 เฉพาะกรณีที่ทุกขั้นตอนสำเร็จ เมื่อ write/read/JSON decode ล้มเหลวจะออกทาง exception ที่บรรทัด 105–106 โดยไม่มี `finally` ปิด handle Named pipe ส่วนนี้ไม่มี timeout parameter ใด ๆ `control_api.py:70–119` ที่ใช้ ctypes ก็ไม่มี overlapped I/O, cancellation หรือ deadline เช่นกัน

ดังนั้น daemon ค้างหรือ pipe server ไม่ตอบสามารถทำให้ CLI และ thread cache ค้างไม่จำกัด และความผิดพลาดซ้ำอาจสะสม handle ใน process อายุยาว การแก้ต้องใช้ bounded I/O, close ใน `finally`, จำกัด frame size, ตรวจ short write/read และแยก timeout ของ connect/write/read ให้ชัดเจน

## Important findings

### I-01 — Rust dashboard เรียกคำสั่งที่ไม่มีอยู่จริง และ subprocess ทำงานใน GUI thread โดยไม่มี timeout

`aegis_dashboard/src/main.rs:115–129` เรียก `Command::new("python").args(["tools/aegisctl.py", "snapshot"])` แต่ parser ใน `tools/aegisctl.py:850–937` ไม่มี `snapshot` และไม่มี `cmd_snapshot` จึงได้ help/exit non-zero และตั้ง `control_available=false` ทุก refresh นอกจากนี้ใช้ `python` จาก PATH ไม่ใช่ absolute interpreter, ใช้ current working directory ที่ caller เลือก และไม่มี timeout/kill policy การเรียก `.output()` บน thread ที่ refresh UI ทุกประมาณหนึ่งวินาทีสามารถทำให้ UI freeze และเปิดโอกาสให้ PATH/cwd ทำให้เรียก executable ผิดตัวได้ ควรใช้ library boundary ที่มี schema เดียวหรือ named-pipe client ที่มี timeout แทน subprocess และเพิ่ม test เปิด dashboard จาก cwd อื่น

### I-02 — Flask dashboard import/stream/template path ไม่สอดคล้องกับการใช้งานจริง และมี DOM injection

`app.py:15–20` import `threading` แต่ `:82–83` เรียก `_thread.start_new_thread` โดยไม่ import `_thread` ทำให้ module import จบด้วย `NameError` ก่อน server start นอกจากนี้มี route `/dashboard` แต่ไม่มี route `/stream` ขณะที่ HTML เรียก `EventSource('/stream')` ที่ `:289–315` และเรียก `eventSource.eventSource.open()` ซึ่งไม่ใช่ API ของ EventSource อีกทั้ง route ใช้ `render_template('index.html')`/`dashboard.html` แต่ source ที่เห็นมีเพียง `jinja_env.from_string()` ที่ `:342–344` ไม่ได้ register template ด้วยชื่อดังกล่าว

ค่าจาก event และ subsystem ถูกต่อเป็น HTML ด้วย `insertAdjacentHTML` และ `innerHTML` โดยไม่ escape ที่ `app.py:299–305,328–332` หาก stream ถูกเติมภายหลังจะเป็น stored/reflected XSS ผ่าน event fields, rule id, IP หรือ subsystem name ควรแก้ import/route/template ให้ทำงานจริง, ใช้ `textContent` หรือ escaping, จำกัด event count และเพิ่ม Flask test client + browser-level test

### I-03 — Lifecycle command module ฆ่า process ตาม image name, clear PID ทั้งหมด และไม่รักษา postcondition

`tools/aegisctl/commands/lifecycle.py:139–174` เมื่อใช้ `--force` เรียก `taskkill /F /IM` กับทุก executable ใน `SUBSYSTEMS` แล้ว `clear_all_pids()` แม้ daemon shutdown จะไม่สำเร็จและไม่ได้ตรวจว่า PID เป็น process ของ AEGIS จริง นี่ต่างจาก root command ที่ปฏิเสธ restart และพยายามให้ daemon เป็น owner (`tools/aegisctl.py:157–205`) จึงเป็น dangerous compatibility path หากถูกเรียกโดยตรง

`commands/lifecycle.py:177–185` เรียก stop/start แล้วคืน 0 โดยไม่ตรวจ return code และ start path ที่ช่วง `:90–136` รัน `cargo build --release` โดยไม่กำหนด timeoutและพิมพ์ build failure แต่เดินหน้าต่อได้ ควรใช้ daemon/service manager owner เดียว, ใช้ PID identity และ process handle, join/ready postcondition, timeout ที่ bounded และ propagate exit code

### I-04 — JSON contract และ error/exit semantics ไม่สม่ำเสมอ

`tools/aegisctl/__init__.py:22–37` มี `structured_error()`/`structured_ok()` แต่หลาย command พิมพ์ข้อความมนุษย์หรือ raw daemon data แทน เช่น health JSON ใน `tools/aegisctl.py:247–260`, ส่วน `control_request()` คืน `{"ok":false,"error":...}` โดยไม่มี `code/state` ที่ `tools/aegisctl/utils.py:187–192` และ `AegisClient.send()` แยก transport exception ออกจาก daemon `{ok:false}` ที่ `client.py:58–86` ไม่ได้ normalize เป็น contract กลาง

ผู้เรียก automation จึงแยก `runtime unavailable`, `authorization denied`, `postcondition failed` และ malformed response ได้ไม่แน่นอน ควรกำหนด envelope/version เดียว, จำกัด error codes, ไม่ผสม raw data กับ structured result และทำ contract tests ทั้ง success, daemon error, malformed JSON, timeout และ authorization denial

### I-05 — Health state ยังมี legacy name/count logic และ artifact presence ไม่ใช่ readiness

`control_api.py:671–732` ใช้ `subsystem_names = ["capture","etw","fim","wfp","pep","control"]` และเทียบ `ready_count` กับ 6 แม้ daemon payload ที่ส่วนอื่นใช้ `rust_pep`, `tier3` และ worker readiness คนละชุด การมีไฟล์ DLL ถูกนับเป็น `artifact_present` ที่ `:635–668` แต่ไม่ใช่ dependency load, provider attestation หรือ host-effect capability โค้ดส่วนใหม่พยายามแยกสามสถานะแล้ว แต่ legacy `compute_health_state()` ยังเสี่ยงทำให้ state degraded/failed ไม่ตรง canonical daemon state ควรใช้ contract schema เดียวและลบ compatibility calculation หลังมี migration test ครบ

### I-06 — Local state mutation ไม่มี locking/atomicity และ dashboard lock ครอบ I/O/IPC

`tools/aegisctl/commands/network.py` และ `policy.py` อ่าน-modify-write JSON หลายขั้นโดยไม่มี file lock หรือ atomic replace ทำให้คำสั่งพร้อมกันสูญเสียรายการหรือเขียนข้อมูลทับกัน `tools/aegisctl/web_dashboard/app.py:73–80` ถือ `_lock` ขณะ `refresh_status_cache()` เรียก pipe, process inspection และอ่าน rules ซึ่งอาจรอหรือค้าง ทำให้ทุก HTTP request รอร่วมกัน ควรย้าย I/O ออกจาก lock, ใช้ atomic temp/replace และจัด concurrency policy ที่ daemon เป็น owner ของ mutable state

### I-07 — Forensic export และ event readers ไม่มีขอบเขต resource ที่ชัดเจน

`tools/aegisctl/commands/forensic.py:23–40` และ root `tools/aegisctl.py:573–595` อ่าน NDJSON ทั้งไฟล์เข้า memory และ export ไปยัง path ที่ caller ให้โดยตรง ไม่มี output root/overwrite policy/size limit ส่วน event follow ใน root `:532–558` อ่านไฟล์ใหม่ทั้งไฟล์ทุก interval ทำให้ latency และ memory โตตาม log การแก้ควรใช้ streaming, bounded tail, field allowlist, output path policy และ atomic export พร้อมระบุ record count/hash

### I-08 — `tools/installer.py` และ operational scripts มี privilege boundary กว้างและ artifact/config contract ไม่ตรวจครบ

NSIS template ใน `tools/installer.py:37–102` ขอ `RequestExecutionLevel admin`, ลบ `*.exe`/`*.dll` ใน `$INSTDIR` และใช้ `taskkill /im aegis_nids.exe /f` ตอน uninstall โดยไม่ผูก process identity หรือ stop/join contract การสร้าง installer ใส่ component comments จาก manifest แต่ payload เป็นรายการ hard-coded และ version/commit คงที่ จึงอาจแพ็ก artifact/config ไม่ตรง manifest ควรสร้าง manifest-driven allowlist, ตรวจ hash/signature, ใช้ service stop protocol และทดสอบ upgrade/uninstall ใน isolated fixture

### I-09 — Legacy/duplicate implementation ทำให้ ABI และ behavior drift

ทุก package command module มี `register_commands(): pass` และ root entrypoint มี parser/handler อีกชุด ทำให้ `tools/aegisctl/commands/network.py`, `policy.py`, `lifecycle.py`, `backup.py`, `forensic.py` ไม่ได้เป็น source เดียวกับ root `tools/aegisctl.py` การมี client สองชุด (`control_api._query_daemon` กับ `AegisClient._send_pipe`) ก็ทำให้ frame size, error shape และ resource cleanup ต่างกัน ควรเลือก implementation เดียว, ลบ dead modules หรือทำ compatibility shim ที่เรียก root API โดยตรง และเพิ่ม import/discovery test ที่ตรวจว่าทุก documented command wire ถึง handler เดียว

## Test และ evidence gaps

1. การตรวจ static syntax ผ่าน `python3 -m py_compile`/`compileall` สำหรับไฟล์ Python ใน scope และคืนค่า 0 แต่ syntax compilation ไม่ตรวจ import-time failure, protocol behavior หรือ Windows API behavior
2. `python3 tests/runtime/test_aegisctl.py` ผ่าน 17 tests และ `python3 tests/runtime/test_wire.py` ผ่าน 18 tests ใน environment นี้ ส่วน `python3 -m unittest tests.runtime.test_health` ผ่าน 21 tests โค้ด health จึงมี unit evidence บางส่วน แต่การรัน `python3 tests/runtime/test_health.py` โดยตรงล้มด้วย `ModuleNotFoundError: No module named 'tests'` แสดงว่า test invocation contract ยังไม่ชัดเจน
3. `pytest` ไม่ได้ติดตั้งใน sandbox จึงไม่ได้รัน `tests/runtime/test_gate_d.py` ผ่าน pytest และไม่มีผล acceptance ของ command matrix จาก test runner ที่โครงการคาดหวัง
4. ไม่มี test ที่สร้าง named pipe จริงเพื่อตรวจ ACL, caller identity, one-request-per-connection, partial read/write, response ใหญ่กว่า 64 KiB, broken pipe, connect timeout, read timeout หรือ handle cleanup
5. ไม่มี test ที่ยืนยันว่า `role`, `request_id`, `nonce`, `issued_at_ms`, `timeout_ms` และ protocol version ถูกส่งจาก Python ถึง daemon และถูก reject เมื่อ stale/replayed/unauthorized; ไม่มี test ว่า TCP compatibility path ถูกปิดใน production
6. ไม่มี fault-injection test สำหรับ response loss หลัง `enforcement.block` host effect เพื่อพิสูจน์ว่า retry ไม่สร้าง duplicate filter และไม่มี test receipt ที่ตรวจ trace/audit/policy/event/runtime-generation linkage
7. ไม่มี end-to-end test ที่ทำให้ `apply_firewall_block()` สำเร็จด้วย valid input; source ปัจจุบันส่ง port 0 และ default policy nonnumeric จึงควรมี regression test ที่จับ defect นี้โดยตรง
8. ไม่มี Flask test client หรือ Rust dashboard test สำหรับ import, `/health`, `/rules`, `/api/status`, `/stream`, template discovery, auth, cache staleness, XSS และ binding address; ไม่มี test เรียก dashboard จาก cwd อื่นหรือเมื่อ `python` ใน PATH ไม่ใช่ interpreter ที่คาดหวัง
9. ไม่มี test สำหรับ backup restore path traversal, absolute path, symlink, duplicate archive entries, signature/manifest authenticity และ partial restore rollback
10. ไม่มี test สำหรับ process identity, force-stop safety, join/readiness postcondition, restart exit propagation, cargo-build timeout หรือ stale PID race
11. ไม่มี concurrency test สำหรับ policy/network JSON updates และ dashboard cache lock จึงยังไม่มีหลักฐานว่า multi-operator หรือ background refresh ปลอดภัย
12. ไม่มี performance budget test สำหรับ full NDJSON reads, forensic export, repeated status retries หรือ GUI subprocess refresh; ไม่มี evidence ว่า control operations ปฏิบัติตาม latency/timeout budget ใน production Windows

## Recommended actions ตามลำดับความสำคัญ

1. **ปิด privileged ambiguity ก่อน:** ลบหรือ compile-out TCP transport ใน production, ทำ request envelope/ACL/freshness/replay ให้เป็น implementation เดียว, ส่ง request id/role จริงถึง daemon และบันทึก audit decision จาก daemon ไม่ใช่ local pre-log
2. **แยก read-only retry ออกจาก mutation:** ห้าม retry `enforcement.block/unblock` แบบ blind; ใช้ idempotency key และ outcome resolution query พร้อม receipt correlation และเพิ่ม fault-injection tests
3. **ทำ enforcement contract ให้ใช้งานได้จริงหรือปิด API:** แก้ port/policy inputs ของ `apply_firewall_block`, สร้าง typed schema validation สำหรับ request และ receipt, ผูก receipt เข้า audit/forensic chain และไม่อ้าง host enforcement หากไม่มี postcondition evidence
4. **ปิด compatibility paths ที่เขียน bookkeeping:** ให้ root และ package commands เรียก handler เดียว; mutation ที่ daemon/PEP ไม่พร้อมต้องคืน non-zero และ structured `RUNTIME_UNAVAILABLE` เสมอ; ลบ no-op `commands/backup.py` หรือทำให้เรียก implementation ที่สร้าง/ตรวจ archive จริง
5. **แก้ dashboard ก่อนเปิดใช้งาน:** import `_thread`/เปลี่ยนเป็น thread API ที่ถูกต้อง, สร้าง `/stream` จริงหรือเอา EventSource ออก, แก้ template registration, ใช้ `get_health_payload()` แทน fabricated RUNNING, bind loopback default, เพิ่ม auth และ escape output
6. **แก้ named-pipe I/O และ resource cleanup:** ใส่ `finally` ปิด handle ทุกทาง, ใช้ overlapped/deadline I/O, จำกัด request/response frame, ตรวจ short write/read และ map timeout/error เป็น exit code ที่แน่นอน
7. **ทำ backup restore ให้ fail-safe:** allowlist paths, canonicalize/containment check, reject traversal/symlink/absolute path, verify signed manifest, stage then atomic promote และเพิ่ม destructive-operation confirmation/policy
8. **รวม lifecycle ownership:** daemon/service manager ต้องเป็น owner เดียวของ start/stop/restart; ไม่ใช้ `taskkill /IM` เป็น normal path; ตรวจ PID identity, wait for join/ready และ propagate failures
9. **ทำ JSON contract และ test matrix ให้เป็น gate:** เพิ่ม schema tests สำหรับทุก command, malformed response, error codes, authorization denial, stale/replay, timeout, receipt และ unavailable state; ทำให้ test invocation ผ่าน `python -m unittest` หรือ pytest อย่างใดอย่างหนึ่งแบบ documented
10. **ลด resource risk:** เปลี่ยน forensic/event reads เป็น streaming bounded readers, ใช้ atomic file writes/locks สำหรับ local state และวัด latency/memory ของ status polling, dashboard refresh และ export ใน Windows CI

## References

[1]: shared/protocol/control_protocol.md "CONTROL_PROTOCOL frozen control-plane contract"
[2]: tools/aegisctl/api/control_api.py "Python control API implementation"
[3]: tools/aegisctl/client.py "Python pipe/TCP client implementation"
[4]: tools/aegisctl.py "Root aegisctl CLI entrypoint and command dispatch"
[5]: tools/aegisctl/web_dashboard/app.py "Flask web dashboard implementation"
[6]: aegis_dashboard/src/main.rs "Rust egui dashboard implementation"
[7]: tools/backup_recovery.py "Backup and restore operational tool"
[8]: tests/runtime/test_health.py "Runtime health unit tests"
[9]: tests/runtime/test_aegisctl.py "aegisctl runtime tests"
[10]: tests/runtime/test_wire.py "Wire/protocol tests"
[11]: docs/runbooks/RB-006-subsystem-health-check.md "Subsystem health check runbook"
[12]: docs/runbooks/RB-002-forensic-query.md "Forensic query runbook"

---

**สถานะหลักฐาน:** รายงานนี้ยืนยันจาก source และ local test ที่ไม่ทำ host mutation เท่านั้น ไม่ได้อ้างว่า WFP หรือ host firewall เปลี่ยนจริง และไม่พบ evidence ใน scope นี้เพียงพอที่จะเรียก control/CLI/dashboard stack ว่า production-ready
