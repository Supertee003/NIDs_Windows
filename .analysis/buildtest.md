# AEGIS NIDS Windows — Build, Deployment, Tests และ Evidence Analysis

**ขอบเขต:** รายงานนี้ตรวจเฉพาะ build graph, manifests/configs, test harness, evidence, Windows deployment และ reproducibility โดยยึด source จริงที่ current HEAD `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5` ไม่ใช้ machine maps ที่อ้าง `688ab566d477105df5f868cee1571fbec77eedfd` เป็น current truth

## 1. ข้อสรุป

Repository มี source และ build intent หลายภาษา แต่ยังไม่มีเส้นทาง **build → package → install → run → verify** ที่ทำซ้ำได้และตรงกันทั้งระบบ ปัจจุบันการตรวจ `python3 tools/truth.py verify` ให้ `TRUTH_INVALID`: `SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`, `CONTRACT_MAP.json`, `EVIDENCE_INDEX.json`, `build_truth.json`, `runtime_manifest.json`, `build_manifest.json` และ `AI_CONTEXT.md` ล้วน stale เมื่อเทียบกับ current HEAD

หลักฐาน runtime ที่มีอยู่ไม่ใช่ proof ว่า golden path ผ่าน กลับแสดงการรันแบบ degraded/failed: `aegis_nids.stderr.log` รายงาน WFP device ไม่พบ, C++ bridge ไม่พบ, ETW start failed, Npcap เปิด adapter ไม่ได้, FIM start failed, named-pipe errors และ segmentation fault ใน trace เดียวกัน อีกทั้ง stack trace อ้าง source line/ฟังก์ชันของ binary เก่าที่ไม่ตรงกับ current `src/platform/win32_pipe.zig` จึงควรจัดเป็น **historical or stale runtime artifact** ไม่ใช่ E5 pass

ข้อสรุปการรับรองคือ **source-level implementation มีอยู่หลายส่วน (E1)** และมี CI/test declarations ที่เป็นโครงสร้าง แต่ **ยังไม่มี current-head E3/E4/E5/E6/E7 proof** สำหรับระบบเต็ม การ build บน sandbox นี้ทำไม่ได้เพราะไม่มี Zig, Cargo, Go หรือ CMake; test harness ที่รันได้เป็น static/proxy tests และมี failure จริงเรื่อง `Rules.json` path

## 2. Build graph ที่ตรวจพบจาก source จริง

### 2.1 Canonical Zig build

`build.zig` ใช้ `src/main.zig` เป็น root และตั้ง default target เป็น Windows x86_64, optimize default เป็น Debug พร้อม link `ws2_32`, `advapi32`, `kernel32`, `user32`, `ole32`, `secur32`, `ntdll`, `tdh`, Npcap (`wpcap`, `Packet`) [1] การ build executable จะพยายาม link Rust PEP จาก `target/release/aegis_pep.dll.lib` และ native ETW/FIM helper จาก `target/helpers` หรือ `build/Release`

กราฟของ Zig มีผลดังนี้:

```text
zig build
  ├─ aegis_nids.exe        <- src/main.zig
  ├─ aegis_fuzz.exe        <- src/fuzz_entry.zig
  ├─ aegis_perf_bench.exe  <- src/perf_bench_main.zig
  ├─ aegis_integration_test.exe <- src/integration_test_main.zig
  └─ zig build test         <- src/all_tests.zig + configs/test/*
```

มีจุดเสี่ยงสำคัญใน graph นี้:

1. `build.zig` อ่าน `configs/test/host_correlator_config.json`, `integration_test_config.json` และ `perf_benchmark_config.json` ด้วย `catch ""`; ไฟล์หายจะกลายเป็น empty option โดยไม่ทำให้ configure fail จึงเปิดทางให้ test graph ผ่านแบบขาด fixture
2. การตรวจ helper ใช้ block ที่คืน `bool` แล้วทดสอบ `if (target_helper_exists != null)` และ `if (cmake_helper_exists != null)` ซึ่งเป็นเงื่อนไขที่เป็นจริงเสมอสำหรับค่า `bool`; ผลคือ `helper_dir` มีแนวโน้มถูกตั้งเป็น `target/helpers` แม้ไฟล์ไม่อยู่ และจึงไม่ได้เลือก `build/Release` ตามเจตนา
3. PEP/helper import library ที่หายถูกลดเป็น warning ไม่ใช่ hard gate แม้ component เหล่านี้เป็น required ใน manifest/CI
4. `addRunArtifact` และ test runner ไม่ได้สร้าง runtime dependency staging ที่ชัดเจนสำหรับ DLL, config และ Npcap; การมี executable จึงไม่เท่ากับการรันได้บน Windows host
5. `build.zig` สร้าง core tools แต่ `Makefile` เรียกเพียง `zig build` และไม่ได้ประกาศ dependency ordering ระหว่าง Cargo/CMake กับ Zig ให้เป็น graph เดียว

### 2.2 Rust PEP

Top-level `Cargo.toml` สร้าง package `aegis_pep` จาก `rust-src/lib.rs` เป็น `cdylib` และ `rlib`, pin edition 2021 และ `rust-version = 1.88`; release profile เปิด LTO, one codegen unit, symbol stripping และ `panic = abort` [2] CI ใช้ `cargo build --release` และ `cargo test --release`

`rust-src/lib.rs` export `aegis_pep_init`, `aegis_pep_shutdown` และ `aegis_pep_enforce` ผ่าน C ABI และ dynamic-load `aegis_wfp_user.dll` [3] นี่เป็น static evidence ว่า PEP boundary มี implementation แต่ยังไม่ใช่ proof ว่า DLL ถูกสร้างจาก current HEAD, loaded โดย current daemon หรือสร้าง Windows firewall effect ได้จริง

มี Shield Rust แยกใน `shield/Cargo.toml` เป็น `sec_monitor.dll` แต่ map จัดเป็น support screening crate และระบุ duplicate PEP/WFP modules ที่ quarantine ไว้ การมี crate นี้ใน tree จึงต้องใช้ negative test ยืนยันว่าไม่มี runtime binding ไปยัง enforcement authority ที่สอง

### 2.3 C/C++ native และ bridge

Top-level `CMakeLists.txt` สร้าง `aegis_wfp_user`, `aegis_etw_helper` และ `aegis_fim_helper` จาก `src/windows/*.c`, link Windows libraries และเปิด `BUILD_KERNEL_DRIVER` เป็น `OFF` โดย default [4] ดังนั้นการรัน CMake ปกติ **ไม่ build kernel WFP callout driver** แม้ repository จะมี driver source

`bridge/CMakeLists.txt` เป็นอีก project หนึ่ง สร้าง `aegis_ipc.dll`, `aegis_bridge.exe`, `aegis_bridge_test.exe`, `aegis_adapter.dll` และ `aegis_adapter_selftest.exe` ไปยัง `dist/` [5] การมี project แยกทำให้ต้องกำหนด artifact staging และ CI upload ให้ชัดเจน แต่ workflow ปัจจุบัน job ชื่อ `c-native-build` ใช้เฉพาะ top-level CMake และ upload เฉพาะ ETW/FIM helper; ไม่ upload WFP user DLL หรือ C++ bridge outputs ให้ job Zig อย่างครบถ้วน

### 2.4 Go Nose และ TypeScript

`nose/go.mod` ใช้ Go 1.22 และ gopacket/bubbletea dependencies [6] `nose/main.go` เป็น executable ที่ทำ TUI/headless/capture modes; `nose/capture.go` เปิด Npcap, serialize 109-byte Canonical Event และส่งไป `\\.\pipe\aegis_nose` ผ่าน `pipe_writer.go` [7] แต่ daemon Zig ไม่ได้ spawn `aegis-nose.exe`; daemon สร้างเพียง reader thread (`runPipeReaderLoop`) ดังนั้น Go Nose ต้องถูก build, deploy และ start แยกต่างหาก จึงจะมี network ingress จริง

`ts_policy/package.json` ระบุ typecheck และชุด node tests ผ่าน `tsx`, โดยไม่มี build output [8] เป็น policy authoring/advisory layer ไม่ใช่ enforcement runtime การมี CI job จึงพิสูจน์เพียง compiler/test contract ไม่พิสูจน์ว่า generated policy ถูกส่งเข้า current Zig daemon ใน production path

### 2.5 Makefile

`Makefile` มี `all: bridge shield nose core mouth`; `bridge` build เฉพาะ `bridge/`, `shield` build shield, `nose` output `dist/nose_dashboard.exe`, `core` เรียก `zig build`, และ `mouth` ใช้ `rustc -O mouth/windows_sec_monitor.rs` [9]

ความไม่สอดคล้องกับ canonical graph คือ:

- manifest/runtime ใช้ชื่อ `aegis-nose.exe` แต่ Makefile สร้าง `nose_dashboard.exe`
- `all` ไม่เรียก top-level CMake จึงไม่สร้าง native ETW/FIM/WFP helpers ที่ `build.zig` ต้องใช้
- `mouth` เป็น optional GUI แต่ไม่มี dependency หรือ output staging ที่เชื่อมกับ installer
- clean recipe ผสม Unix `rm` กับ Windows `del` และไม่ใช่ cross-platform reproducible command
- ไม่มี lock/verify step สำหรับ artifact digest, signing, package content หรือ runtime dependency closure

## 3. Actual call graph และ static/runtime separation

### 3.1 Current production entry path

จาก current source call graph ที่ตรวจได้คือ:

```text
src/main.zig:main
  -> platform/win32_service.mainEntry
     -> StartServiceCtrlDispatcherW (เมื่อถูก SCM เรียก)
     -> daemon.runDaemon (console fallback หรือ serviceMain)
        -> security self-check
        -> capability probe
        -> load configs/Rules.json
        -> load configs/policies.json
        -> init PepEnforcer + ActionDispatcher
        -> bridge_init.initAll()
        -> spawn legacy sensor thread
        -> spawn pipelineLoop
        -> spawn nose_pipe_reader.runPipeReaderLoop
        -> spawn ETW/FIM/Registry worker threads
        -> bounded readiness barrier
        -> platform/win32_pipe.serveWindowsPipe
        -> RuntimeSupervisor stop + reverse-order join
```

`src/main.zig` เองเป็น entry decision เท่านั้น; `daemon.zig` เป็น startup owner และ `RuntimeSupervisor` ถือ thread handles ของ pipeline, sensor, Nose reader, ETW, FIM และ Registry [10] การมีโครงสร้างดังกล่าวเป็น **E1 static ownership evidence** เท่านั้น เพราะยังไม่มี current Windows run ที่ยืนยัน readiness, stop, join และ postcondition ครบ

### 3.2 Actual event processing path

เมื่อ event เข้าคิว `src/pipeline/event_processor.zig` จะทำ:

```text
queue.popEvent
  -> flow.lookupOrCreate
  -> signature match (event metadata หรือ payload ถ้ามี)
  -> anomaly detector
  -> threat tracker / incident
  -> PolicySet.evaluate
  -> PepEnforcer.enforce
  -> ActionDispatcher.dispatch
  -> structured audit trace
  -> ForensicRing.append
```

นี่เป็น static call graph ที่ชัดเจน [11] แต่ Go Nose path กับ daemon path ยังไม่ใช่ process graph เดียว เพราะไม่มี current service/deployment step ที่ start Go Nose และไม่มี test ที่ inject frame ผ่าน actual Windows named pipe แล้วตรวจ event ID เดียวกันถึง forensic append

### 3.3 Go Nose ingress

`nose_pipe_reader.zig` สร้าง server ที่ `\\.\pipe\aegis_nose`, อ่าน u32 length + 109-byte frame, deserialize/validate, ตรวจ duplicate/non-monotonic event IDs แล้วเรียก `pipeline_queue.pushCanonicalEvent` [12] สิ่งนี้เป็น static protocol evidence และมี counters ที่เหมาะสม แต่ runtime proof ต้องแสดง `frames_read`, `frames_rejected`, `frames_submitted`, `events_processed`, event ID และ forensic sequence จาก **หนึ่ง run เดียวกัน**

### 3.4 Static assertions ที่ไม่ใช่ runtime proof

`tests/test_golden_path.py` ประกาศชื่อ scenarios จำนวนมาก แต่หลาย scenario เพียงตรวจว่าไฟล์/config มีอยู่หรือคืน `True` พร้อมข้อความว่า unit test อื่นครอบคลุม เช่น anomaly, injection, registry, federation และ ring wrap ไม่ได้ spawn current daemon [13] ใน sandbox การรันจริงให้ 9 PASS/1 FAIL; failure คือ `Rules.json` ที่ root ไม่มี (ไฟล์จริงอยู่ `configs/Rules.json` และ `config/Rules.json`) ส่วน Zig/Cargo ไม่ได้รันเพราะไม่มี toolchain และ harness นับ “not available; skipped” เป็น pass ใน scenario

`tests/runtime/README.md` แยก static tests กับ live tests ถูกต้อง และระบุว่า live tests จะ skip เมื่อไม่มี binary หรือ named-pipe support [14] ดังนั้นผล static suite ห้ามแปลงเป็น E3/E5 claim

## 4. Tests และ harness

### 4.1 CI ที่ประกาศ

`.github/workflows/ci.yml` กำหนด Windows jobs สำหรับ Zig, Rust PEP, C native, Python/Cython, Go Nose, Go aggregator, TypeScript และ security scan; `ci-matrix` ใช้ `always()` และ `--needs-json` เพื่อ mark failure/skipped/cancelled เป็น fail สำหรับ required jobs [15] การรัน local `python3 tools/ci_coverage.py --json` ให้ PASS เพราะ checker ตรวจเพียงว่า job IDs ปรากฏใน YAML; ไม่ได้อ่าน GitHub run result จึงเป็น **E1 declaration proof** ไม่ใช่ CI execution proof

จุดที่ workflow ยังไม่ปิด:

- `zig-build-test` download helper artifacts จาก `c-native-build` แต่ c-native job upload ETW/FIM เท่านั้น ไม่ upload WFP user DLL และไม่ upload C++ bridge
- `shield-build` มีอยู่ใน workflow แต่ `ci_coverage.json` จัด shield เป็น optional support และ job ไม่ถูกผูกใน package-release needs
- Cython ถูก build ภายใน Python job แต่ไม่มี dedicated `cython-build-test`; checker รายงาน optional gap
- Npcap SDK ถูก download จาก URL โดยไม่มี checksum/signature verification
- package-release เรียก `python tools/installer.py --package --output aegis_setup.exe` แต่ `tools/installer.py` รองรับเพียง `--generate` และ `--nsi`; จึงเป็น command-line blocker ที่ทำให้ package job fail ก่อนสร้าง installer

### 4.2 Test graph ของ Zig

`build.zig` root test คือ `src/all_tests.zig` และ link `tdh`, `advapi32`, `ntdll`, helper libraries และ optional PEP import library [1] อย่างไรก็ตาม local evidence ไม่มี output: `zig-test.stdout.log` ว่าง และ `zig_build.log` ว่าง ขณะที่ `build-error.log` ระบุ `zig : error: FileNotFound` จาก Windows command ดังนั้นไม่มี E2 result ที่ยืนยันจาก current HEAD

### 4.3 Python/runtime tests

Python source/test structure มี tests จำนวนมากแยก contracts, adapters, e2e, forensics, PEP, policy signing, release, reliability, runtime, security และ WFP แต่ sandbox นี้ไม่มี `pytest` (`No module named pytest`) จึงไม่สามารถ execute suite ได้ การมี `__pycache__` หรือ recorded PASS ใน evidence index ไม่ใช่ current run proof

### 4.4 Test mismatch ที่เห็นจาก source

- `test_golden_path.py` ใช้ root `Rules.json` ขณะที่ daemon ใช้ `configs/Rules.json`
- `tests/e2e/test_t14_windows_golden_path.py` ตรวจ manifest entries/path labels และคำว่า `REAL`; เป็น manifest/static architecture test ไม่ได้เปิด Npcap, named pipe, PEP หรือ WFP
- `tests/adapters/test_t9_windows_adapters.py` ระบุเองว่า strategy เป็น architectural, not host-verified real calls แม้ test names จะใช้คำว่า REAL/host-verified
- `tests/release/test_t17_perf_ci_installer.py` ตรวจข้อความและไฟล์ใน source; บาง assertion คาด `file_directive` และ generated NSIS แต่ `installer.py` ไม่ได้ใช้ `file_directive` เพื่อสร้าง File directives จาก artifact list จริง

## 5. Windows deployment analysis

### 5.1 `tools/deploy_windows.py` เป็น blocker

สคริปต์กำหนด `SOURCE_ROOT = Path(__file__).parent` ซึ่งเมื่ออยู่ใน `tools/` จะชี้ไปที่ `.../NIDs_Windows/tools` ไม่ใช่ repository root [16] ดังนั้น `deploy()` จะค้น `tools/src`, `tools/rust-src`, `tools/build.zig` และไฟล์ระดับ root ใน directory ผิด ทำให้ deployment ที่อ้างว่า mirror repository ไม่ reliable

แม้แก้ root แล้ว รายการที่ copy ยังไม่ครบ canonical runtime: ไม่ copy `nose/`, `bridge/`, `brain/`, `ts_policy/`, `scripts/`, `dist/`, `target/` หรือ prebuilt native DLLs โดย `build()` ก็รันเพียง Zig, top-level Cargo และ CMake ไม่ build Go Nose หรือ C++ bridge; target ที่ได้จึงไม่สามารถสร้าง golden path ตาม manifest ได้

### 5.2 Service install และ working directory

`install_service()` สร้าง service ให้ชี้ไป `zig-out/bin/aegis_nids.exe` แต่ไม่ได้กำหนด working directory/profile path และ daemon เปิด `configs/Rules.json` กับ `configs/policies.json` เป็น relative paths [10] Windows Service Manager อาจใช้ working directory ที่ต่างจาก repository ทำให้ service รายงาน 0 rules หรือ empty policy ได้แม้ไฟล์ติดตั้งอยู่ครบ นอกจากนี้ service command ไม่ได้ stage DLL search directories หรือ Go Nose child process

### 5.3 Installer มีหลายรุ่นที่ขัดกัน

มีอย่างน้อยสาม packaging authorities:

1. `tools/installer.py` มี generated NSIS template version 5.0.0
2. root `installer.nsi` เป็น legacy hand-written script version 1.0.0 และอ้างไฟล์เก่าที่ไม่มีอยู่ เช่น `nids_analyze.zig`, `nids_capture.zig`, `nids_main.zig`, root `windows_brain.py`, root `aegis_daemon.py` และ `src\lib.rs`
3. `scripts/verify_release.ps1` คาด package รุ่นเก่าที่มี `bin\aegis_nids.exe`, `src\release_info.zig`, `src\nids_main.zig` และ `release-manifest.json` ซึ่งไม่ตรงกับ current `zig-out/bin`, `src/main.zig` และ `build_manifest.json`

`tools/installer.py` อ่าน `build_manifest.json` เพียงเพื่อใส่ component comments แล้ว append template คงที่; `manifest_components()` ไม่ได้ generate File directives ของทุก component และ template omit `aegis_etw_helper.dll`, `aegis_fim_helper.dll`, Go Nose, C++ bridge, Python runtime/CLI, driver, service registration และ signing metadata [17] จึงยังไม่ใช่ manifest-driven release package จริง

### 5.4 Driver and enforcement deployment

Top-level CMake ไม่ build kernel driver (`BUILD_KERNEL_DRIVER OFF`) และ installer generator ไม่ package/sign/install driver service ส่วน `aegis_wfp_user.dll` เป็น user-mode helper; การมี PEP decision หรือ DLL จึงไม่พิสูจน์ WFP host effect ต้องมี separate WDK build, signing, service registration, block/unblock observation และ rollback

## 6. Evidence levels

Repository นิยาม E0–E7 ว่า E0 no evidence, E1 static inspection/AST, E2 unit proof, E3 component integration, E4 system integration, E5 Windows host verification, E6 production simulation และ E7 release verification [18] การจัดระดับตาม current source และ artifacts มีดังนี้

| ระดับ | สิ่งที่มีจริง | การตีความที่อนุญาต | สิ่งที่ยังห้ามสรุป |
|---|---|---|---|
| E0 | ไม่มี current proof สำหรับ full release | ยังไม่มีหลักฐาน | ห้ามอ้าง production-ready |
| E1 | source/build/CI declarations, static tests, `ci_coverage.py`, current call graph | implementation/structure exists | ไม่ใช่ runtime success |
| E2 | historical entries ใน `EVIDENCE_INDEX.json`; local harness static checks | อาจเป็น unit proof ของ revision เดิม ถ้าผูก commit ได้ | ใช้กับ current HEAD ไม่ได้โดยอัตโนมัติ |
| E3 | ไม่มี current artifact ที่แสดง cross-component run | ต้องสร้างใหม่ | ห้ามเรียก static contract test ว่า integration |
| E4 | ไม่มี current full system run | ต้องสร้างบน controlled Windows integration environment | ห้าม claim golden path |
| E5 | `aegis_nids.stderr.log` แสดง Windows execution แต่ failed/degraded และ binary/source mismatch; EVT-026 อ้าง bridge 36/36 ที่ historical | เป็น failed runtime observation เท่านั้น | ไม่ใช่ current Windows host pass |
| E6 | ไม่พบ production simulation package/result ที่ผูก current HEAD | none | ห้ามอ้าง operational simulation |
| E7 | ไม่มี clean-room release/install/rollback evidence current HEAD; package command mismatch | none | ห้ามอ้าง release verified |

หลักฐาน E2/E5 ใน `EVIDENCE_INDEX.json` จำนวนมากผูกกับ `ec12182`, `e6de1ae`, `fdb4c2b` หรือ `688ab...` ไม่ใช่ `46b93dc...` จึงเป็น historical evidence จนกว่าจะ re-run และ attach artifact digest, environment, command และ raw output ใหม่

## 7. Stale artifacts และ provenance findings

### 7.1 Machine maps

`SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`, `CONTRACT_MAP.json`, `EVIDENCE_INDEX.json`, `build_truth.json` และ `runtime_manifest.json` มี `head_sha = 688ab...` ตามที่ task กำหนดให้ถือว่า stale [19] บาง map ยังประกาศว่า golden path เป็น “REAL host-verified Windows E2E” ทั้งที่ current runtime log แสดง failures จึงต้องไม่ใช้เป็น authority

`build_truth.json` ยิ่งขัดแย้งภายในตัวเอง: field `head_sha` เป็น `688ab...`, note บอก synchronized ไป `48eb2a...`, status เป็น `TRUTH-001_SYNCED` แต่ `tools/truth.py verify` บน current checkout รายงาน stale ทั้งไฟล์

### 7.2 Build manifest

`build_manifest.json` ระบุ `source_commit = 0a7418b` และ component commits เดียวกัน ไม่ใช่ current HEAD [20] การรันจริง `python3 tools/release_engineering.py --verify` ตรวจ 339 artifact และพบ digest mismatch 7 รายการ: `build.zig`, `scripts/aegis_console.py`, `scripts/aegis_event_gen.py`, `scripts/aegis_graph.py`, `shield/Cargo.lock`, `tools/aegisctl.py` และ `tools/aegisctl/api/control_api.py`

ตัว verifier เองบันทึกว่า `--manifest` มี artifact-set drift: collector ยังมองหา `core/` และ `config/`, omits `src/` และ `configs/`, และอาจหยิบ generated Cython output ดังนั้นการ regenerate manifest โดยไม่ทำ reconciliation จะทำลาย provenance แทนที่จะแก้ stale state [21]

### 7.3 SBOM

`sbom.spdx.json` สร้างวันที่ 2026-09-06 ก่อน current HEAD และไม่มี source commit field ที่เชื่อมทั้งเอกสารกับ HEAD นอกจากนี้ `release_engineering.py` สร้าง SPDXID ด้วย Python built-in `hash(path)` ซึ่ง randomized ต่อ process; การ generate ซ้ำจึงไม่ deterministic แม้ file contents เท่าเดิม [21] SBOM นี้จึงเป็น historical inventory ไม่ใช่ E7 provenance proof

### 7.4 Runtime logs and binaries

`aegis_nids.stderr.log` มีข้อความ `loaded 0 rules`, WFP error 0x2, bridge missing, ETW/FIM failures, Npcap error 123 และ named-pipe ACL/creation errors ตามด้วย segmentation fault [22] stack trace อ้าง `SetEntriesInAclW` ใน line 181 แต่ current source line 181 เป็น `GetLastError()` หลัง `CreateNamedPipeW`; จึงไม่ควรผูก log นี้กับ current binary/source โดยไม่มี binary SHA-256 และ build manifest

## 8. Reproducibility assessment

### มีสิ่งที่ช่วย reproducibility

- CI ระบุ versions หลัก: Zig 0.13.0, Rust 1.88.0, Python 3.11, Go 1.22, Node 20 และ MSVC 19.38+
- Cargo.lock และ package scripts มีอยู่
- `tools/release_engineering.py --verify` มีแนวคิด normalized LF hashing และตรวจ missing/mismatch
- `ci-matrix` มี semantics ที่ออกแบบให้ required skipped/failed เป็น failure

### สิ่งที่ทำให้ทำซ้ำไม่ได้ในปัจจุบัน

1. current truth artifacts stale และ build manifest source commit ไม่ตรง HEAD
2. build graph แยก Zig/Cargo/top-level CMake/bridge CMake/Go โดย dependency staging ไม่เป็น graph เดียว
3. `tools/deploy_windows.py` ชี้ source root ผิดและไม่ deploy canonical Go/bridge/runtime dependencies
4. package-release เรียก options ที่ installer ไม่รองรับ
5. installer/verify-release มี package layout หลายรุ่น
6. daemon ใช้ relative config/DLL paths และ service install ไม่กำหนด working directory
7. Npcap download ไม่มี checksum pin; WDK/driver/signing prerequisites ไม่ถูกปิดใน build gate
8. release manifest มี wall-clock `build_date` และ hostname; SBOM SPDXID ใช้ randomized Python hash; ZIP metadata/mtime ไม่ถูก normalize
9. local test harness treats missing Zig/Cargo as pass-like skipped output และ golden-path scenarios หลายตัวเป็น static proxies
10. no current binary digest, PDB/build ID, host identity, command transcript, health before/after, event ID chain, WFP filter ID หรือ rollback observation ที่ผูกเป็น evidence bundle เดียว

## 9. Blockers และ risk register

| ID | ความรุนแรง | Finding | ผลกระทบ |
|---|---|---|---|
| B-01 | P0 | Truth maps/evidence/build manifest stale | ทุก claim ที่อิง map/evidence อาจชี้ revision ผิด |
| B-02 | P0 | Current-head release digest verification fails 7 files | provenance/release gate ไม่ผ่าน |
| B-03 | P0 | Installer package command mismatch and static template | CI release cannot reliably produce complete installer |
| B-04 | P0 | Windows deploy script uses `tools/` as source root | deployment may copy nothing or incomplete tree |
| B-05 | P0 | Go Nose is not spawned/deployed by service path | canonical network ingress absent in installed runtime |
| B-06 | P0 | Native/bridge artifacts not unified in CI/package | runtime DLL loading and C ABI path unproven |
| B-07 | P0 | Runtime log records WFP/ETW/FIM/Npcap/pipe failures and segfault | current Windows runtime safety not established |
| B-08 | P1 | Relative config/DLL lookup under SCM | service can start with 0 rules/empty policy or fail to load DLLs |
| B-09 | P1 | Top CMake leaves kernel driver disabled | no driver build/sign/install/effect proof |
| B-10 | P1 | Static tests and manifest assertions are over-labeled as REAL/host proof | false confidence and stale evidence propagation |
| B-11 | P1 | Build helper existence check is logically incorrect | wrong library directory selection and link failures |
| B-12 | P1 | `Rules.json` path differs between daemon and golden-path harness | test failure and config drift |
| B-13 | P1 | Build/test config files are silently replaced with empty strings when absent | false green or incomplete test graph |
| B-14 | P1 | Multiple legacy installer/release layouts | clean-room verification cannot be deterministic |
| B-15 | P2 | SBOM IDs and archives are not deterministic | byte-for-byte release reproducibility fails |

## 10. Required next actions

1. **Rebaseline truth first.** Regenerate all maps, `build_truth.json`, `runtime_manifest.json`, `build_manifest.json`, `EVIDENCE_INDEX.json` and SBOM from current HEAD; run `python tools/truth.py verify` and require `TRUTH_VALID`. Do not edit source to accommodate old maps.
2. **Create one build orchestrator.** Make one Windows CI/release command build Rust PEP, top-level native helpers, bridge, Go Nose, Zig core, optional Shield, and TypeScript checks in dependency order. Fail hard on missing required artifact and publish exact SHA-256/digital signature.
3. **Fix deployment root and closure.** Make `deploy_windows.py` resolve repository root with `Path(__file__).resolve().parents[1]`; copy/build `nose`, `bridge`, configs, native DLLs, PEP DLL/import library, driver package and CLI. Stage an explicit runtime directory rather than relying on CWD.
4. **Converge packaging.** Retire root legacy `installer.nsi` and stale `verify_release.ps1`, or regenerate them from a single manifest-driven package schema. Add a supported `--package --output` interface or change CI to the actual interface. Include Go Nose, ETW/FIM, bridge, config, trust store, service registration, driver/signature metadata and rollback files.
5. **Make service paths absolute.** Resolve executable directory at startup and use it for configs, DLL search, logs, and Go Nose launch. Add a service test that starts from `C:\Windows\System32`-like CWD and verifies non-empty rules/policy and truthful health.
6. **Prove the real process graph.** On a clean Windows host, build from current HEAD, start the installed service plus canonical Go Nose, inject one known fixture, and collect `event_id`, pipe counters, detector/policy result, PEP request ID, WFP result/filter ID, forensic sequence and audit hash in one evidence bundle.
7. **Separate E-levels in CI.** Label static contract/AST checks E1, executed unit tests E2, component integration E3, system integration E4, Windows host E5, production simulation E6 and release verification E7. A manifest string `status=REAL` must never promote evidence level.
8. **Replace proxy tests with fail-closed tests.** `test_golden_path.py` should spawn or explicitly mark unavailable instead of returning PASS for a static claim. Missing Zig/Cargo/pytest must fail the required build/test lane, not become a pass-like skip.
9. **Fix current graph defects.** Correct `build.zig` helper bool checks, make missing `configs/test/*` fatal, align `Rules.json` path, and make CI upload all native artifacts consumed by Zig/Rust.
10. **Produce release evidence.** Run clean-room install/upgrade/rollback/uninstall with package hash, installer log, service state, driver state, WFP effect, health before/after, and post-rollback no-residue checks. Only then claim E7.

## References

[1]: ./build.zig "Zig build graph, tests, helper and PEP linking"
[2]: ./Cargo.toml "Rust PEP manifest and release profile"
[3]: ./rust-src/lib.rs "Rust PEP C ABI and WFP adapter"
[4]: ./CMakeLists.txt "Top-level native Windows helper build"
[5]: ./bridge/CMakeLists.txt "C++ bridge and adapter build"
[6]: ./nose/go.mod "Go Nose module manifest"
[7]: ./nose/main.go "Go Nose entrypoint"; ./nose/capture.go "Go Nose capture and canonical event path"; ./nose/pipe_writer.go "Go Nose named-pipe writer"
[8]: ./ts_policy/package.json "TypeScript policy scripts"
[9]: ./Makefile "Multi-language convenience build targets"
[10]: ./src/main.zig "Process entry"; ./src/platform/win32_service.zig "SCM/console dispatch"; ./src/daemon.zig "Runtime supervisor and worker startup"
[11]: ./src/pipeline/event_processor.zig "Detection, policy, PEP, dispatch, audit and forensic call graph"
[12]: ./src/capture/nose_pipe_reader.zig "Canonical Go Nose named-pipe reader"
[13]: ./tests/test_golden_path.py "Golden-path harness and static proxy scenarios"
[14]: ./tests/runtime/README.md "Static versus live runtime tests"
[15]: ./.github/workflows/ci.yml "Declared CI jobs and release workflow"
[16]: ./tools/deploy_windows.py "Windows deployment and service installation script"
[17]: ./tools/installer.py "NSIS installer generator"
[18]: ./EVIDENCE_INDEX.json "Evidence-level definitions and historical evidence registry"
[19]: ./SYSTEM_MAP.json "Stale machine system map"; ./FLOW_MAP.json "Stale machine flow map"; ./AUTHORITY_MAP.json "Stale machine authority map"; ./CONTRACT_MAP.json "Stale machine contract map"
[20]: ./build_manifest.json "Historical build manifest and artifact digests"
[21]: ./tools/release_engineering.py "Manifest/SBOM generation and verification"
[22]: ./aegis_nids.stderr.log "Recorded Windows runtime stderr/log evidence"
