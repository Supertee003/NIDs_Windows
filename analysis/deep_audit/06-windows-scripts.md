# AEGIS Windows NIDS/IPS — Deep Audit: Windows scripts, installer และ release engineering

## ขอบเขตและข้อสรุป

รายงานนี้ตรวจเฉพาะ Windows scripts, installer, release engineering, driver build/install path และ Windows-native source ที่อยู่ในขอบเขตที่ระบุ โดยใช้ repository `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows` เป็น source of truth และยืนยันรายการด้วย `git ls-files` จากนั้นอ่านโค้ดจริงพร้อม line numbers ไม่ใช้ชื่อไฟล์หรือ handoff เป็นหลักฐานแทนโค้ด

**ข้อสรุปหลัก:** ยังไม่มีหลักฐานเพียงพอที่จะเรียก build/install/release path นี้ว่า production-ready. มีเส้นทาง build และ package หลายชุดที่ใช้ layout และ artifact คนละแบบ. เส้นทาง WDK แบบ PowerShell, เส้นทาง batch, NSIS รุ่นเก่า, NSIS ที่อยู่ใน `installer/` และ bundle ที่อยู่ใน `release/` ไม่ได้เป็น pipeline เดียวกัน. จุดที่มีผลกระทบสูงสุดคือ installer บางชุดไม่ติดตั้ง core service หรือ WFP driver ให้ครบ, การ signing ที่มีอยู่เป็น test signing พร้อม password hard-coded, rollback ไม่เป็นธุรกรรมและไม่ restore service state, device object ไม่มีหลักฐาน ACL ที่จำกัด caller, และ driver มี persistent WFP filter ที่ cleanup ไม่ครอบคลุมทั้งหมด.

การตรวจนี้ **ไม่รัน controlled host block**, ไม่ใช้ `netsh`, ไม่เปลี่ยนระบบภายนอก และไม่ถือ `legacy block_ip` หรือ bookkeeping เป็นหลักฐานว่า enforcement ใช้งานได้. การกล่าวถึง WFP block path ด้านล่างเป็นการวิเคราะห์ความปลอดภัยและ lifecycle ของ code ที่มีอยู่เท่านั้น ไม่ใช่การยืนยันผล enforcement บน host

## Files reviewed

`git ls-files` พบไฟล์ใน scope ทั้งหมด 133 ไฟล์. ไม่พบ tracked file ใต้ `build/**/*`; build output ที่มีอยู่ใน working tree จึงไม่ใช่ source-controlled input ของ repository. รายการที่อ่านมีดังนี้

```text
Makefile
bridge/CMakeLists.txt
bridge/__init__.py
bridge/aegis_adapter.cpp
bridge/aegis_adapter.hpp
bridge/aegis_adapter_selftest_main.cpp
bridge/aegis_bridge_ctypes.py
bridge/aegis_bridge_main.cpp
bridge/aegis_bridge_test.cpp
bridge/aegis_ipc.cpp
bridge/aegis_ipc.hpp
bridge/aegis_packet_parser.cpp
bridge/aegis_packet_parser.hpp
bridge/bridge_status.py
drivers/minifilter/aegis_minifilter.c
drivers/minifilter/aegis_minifilter.h
drivers/minifilter/aegis_minifilter.inf
drivers/minifilter/aegis_minifilter_comm.c
drivers/minifilter/aegis_minifilter_file.c
drivers/minifilter/aegis_minifilter_proc.c
drivers/wfp_callout/aegis_minifilter.inf
drivers/wfp_callout/aegis_wfp.c
drivers/wfp_callout/aegis_wfp.h
drivers/wfp_callout/aegis_wfp.inf
drivers/wfp_callout/aegis_wfp_callout.c
drivers/wfp_callout/aegis_wfp_comm.c
installer.nsi
installer/aegis.nsi
mouth/.gitignore
mouth/Cargo.lock
mouth/Cargo.toml
mouth/README_DEPLOY.txt
mouth/build_mouth.bat
mouth/windows_sec_monitor.rs
nose/README_DEPLOY.txt
nose/canonical.go
nose/canonical_test.go
nose/capture.go
nose/cleanup_nose_mouth.bat
nose/collectors.go
nose/go.mod
nose/go.sum
nose/golden_path_ffi.go
nose/ipc_reader.go
nose/main.go
nose/model.go
nose/pipe_writer.go
nose/run_nose.bat
nose/signature_classifier.go
nose/styles.go
release/aegis-nids-windows-6.0.0-20260916_223148/README.txt
release/aegis-nids-windows-6.0.0-20260916_223148/configs/Rules.json
release/aegis-nids-windows-6.0.0-20260916_223148/configs/policies.json
release/aegis-nids-windows-6.0.0-20260916_223148/manifest.json
release/aegis-nids-windows-6.0.0-20260916_223148/scripts/install_aegis.ps1
scripts/Dashboard.py
scripts/add_web_evidence.py
scripts/aegis.bat
scripts/aegis.ps1
scripts/aegis_alerts.py
scripts/aegis_api.py
scripts/aegis_block.py
scripts/aegis_console.py
scripts/aegis_console_pro.py
scripts/aegis_daemon.py
scripts/aegis_defcon.py
scripts/aegis_event_gen.py
scripts/aegis_graph.py
scripts/aegis_metrics.py
scripts/aegis_notifier.py
scripts/aegis_rules.py
scripts/aegis_status.bat
scripts/aegis_status.py
scripts/aegis_unblock.py
scripts/analyze_existing.py
scripts/analyze_vectors.py
scripts/build_all.bat
scripts/build_and_check.ps1
scripts/build_drivers.bat
scripts/check_brain.py
scripts/check_evidence.py
scripts/check_summary.py
scripts/check_vec.py
scripts/clean_aegis.bat
scripts/create_test_vectors.py
scripts/diag_aegis_dirs.bat
scripts/diag_deep.bat
scripts/doc_checker.py
scripts/fix_console.py
scripts/fix_console2.py
scripts/install_aegis.ps1
scripts/install_drivers.bat
scripts/ml_train.py
scripts/package_release.ps1
scripts/pep_analysis.py
scripts/read_vectors.py
scripts/release_package.ps1
scripts/reload_rules_control.ps1
scripts/run_aegis.bat
scripts/setup_aegis.bat
scripts/stop_aegis.bat
scripts/summary_detection_path.py
scripts/tests/aegis_mouth_test.py
scripts/tests/aegis_nose_test.py
scripts/tests/test_e2e.py
scripts/update_console.py
scripts/validate_operator_cli.py
scripts/verify_release.ps1
scripts/wdk_build_production.ps1
scripts/wfp_service.ps1
scripts/wfp_sign.ps1
scripts/windows_host_verification.py
src/windows/aegis_wfp.c
src/windows/cpp_adapter.zig
src/windows/etw_native.c
src/windows/etw_realtime.zig
src/windows/fim.zig
src/windows/fim_native.c
src/windows/hids_engine.zig
src/windows/hids_process_monitor.zig
src/windows/host_telemetry.zig
src/windows/host_telemetry_detectors.zig
src/windows/host_telemetry_mock.zig
src/windows/host_telemetry_scenarios.zig
src/windows/injection_detector.zig
src/windows/ips_canary.zig
src/windows/ips_canary_order.zig
src/windows/ips_simulation.zig
src/windows/registry_monitor.zig
src/windows/registry_trie.zig
src/windows/wfp_ioctl.c
src/windows/win32_io.zig
src/windows/windows_adapters.zig
```

ไฟล์ที่มีอยู่จริงใน working tree แต่ไม่อยู่ใน `git ls-files` ได้แก่ binary ใต้ `release/aegis-nids-windows-6.0.0-20260916_223148/runtime/` และ `drivers/`, รวมถึง `release/aegis-nids-windows-6.0.0-20260916_223148.zip`. ผมตรวจ hash/size ของ binary ตาม manifest แล้วพบว่าค่าที่ประกาศตรงกับไฟล์ที่มีอยู่ แต่เนื่องจากไฟล์เหล่านี้ไม่ tracked จึงยังไม่มีหลักฐานว่า binary เหล่านั้นสร้างจาก commit ปัจจุบันหรือจาก pipeline ที่ตรวจสอบย้อนกลับได้

## Architecture และ call/data/control flow

### 1. Build flow

`Makefile` กำหนด `all` เป็น `bridge`, `shield`, `nose`, `core`, `mouth` (`Makefile:1-19`). `bridge` เรียก CMake จาก `bridge/` และวาง output ใน `dist/` ตาม `bridge/CMakeLists.txt:28-39`. `shield` ใช้ Cargo, `nose` ใช้ Go, `core` ใช้ `zig build`, และ `mouth` ใช้ `rustc` โดยตรง. เส้นทางนี้ไม่เรียก WDK driver build และไม่ pin compiler path หรือ environment ให้เป็น deterministic

`scripts/build_all.bat:54-224` เป็นอีก orchestration หนึ่ง. มันตรวจว่า toolchain มีหรือไม่ แล้ว **skip** component ที่หายไป และ exit สำเร็จหากมี component ใด component หนึ่งสร้างได้ (`build_all.bat:56-61`, `78-92`, `112-126`, `203-224`). ดังนั้นผล `0` ของสคริปต์นี้ไม่ได้หมายถึงชุด artifact ที่ product ต้องใช้สร้างครบ. `scripts/build_and_check.ps1:17-36` สร้าง native helper ผ่าน CMake แล้วเรียก `zig build-exe` แบบ `-ODebug` และ link path ที่มาจาก `target/release`, `build/Release` และ `%LOCALAPPDATA%/NpcapSDK` ซึ่งไม่ใช่ release build ที่ reproducible เดียวกัน

สำหรับ driver มีสองเส้นทางที่ไม่สอดคล้องกัน. `scripts/build_drivers.bat:87-125` ค้นหา WDK 10/11 แบบ hard-coded และ `scripts/build_drivers.bat:162-210` เรียก `cl`/`link` เอง. `scripts/wdk_build_production.ps1:23-52` ใช้ `vswhere -latest`, เลือก MSVC directory ล่าสุด และ `scripts/wdk_build_production.ps1:55-169` เลือก WDK version ล่าสุดที่มี `ntoskrnl.lib` พร้อมค้นหา `fwpmk.lib` แบบ dynamic. เส้นทาง PowerShell นี้ output เป็น `build\x64\wfp\aegis_wfp.sys` (`wdk_build_production.ps1:200-203`), แต่ batch path output เป็น `build\drivers\wfp\aegis_wfp.sys` และ copy ไป `build\Release` (`build_drivers.bat:79-84`, `198-215`). ไม่มี build graph เดียวที่ยืนยันว่า output ใดคือ driver ที่จะเข้า release

### 2. Windows runtime and privilege boundary

เมื่อ `DriverEntry` ทำงาน driver จะสร้าง device object และ symbolic link, กำหนด IRP handlers, จอง non-paged ring buffer และ register WFP callout/filter (`drivers/wfp_callout/aegis_wfp.c:52-105`). WFP classify callback อ่าน 5-tuple แล้วเขียน event header 40 bytes ลง ring buffer ก่อน `FWP_ACTION_PERMIT` (`drivers/wfp_callout/aegis_wfp_callout.c:18-114`). User-mode C helper เปิด `\\.\AegisWfpDevice` แล้วเรียก `DeviceIoControl` (`src/windows/wfp_ioctl.c:20-26`, `74-161`). Zig binding ใน `src/policy/wfp_ioctl.zig:104-225` เปิด device แบบ `GENERIC_READ` และอ่าน events/stats เพื่อนำเข้ารันไทม์หลัก

ส่วน FIM ใช้ `ReadDirectoryChangesW` ใน thread ของ `src/windows/fim_native.c:26-54`, ส่งข้อมูลผ่าน C ABI ไปยัง Zig/Cython หรือ adapter layer. C++ bridge สร้าง DLL และ executable จาก `bridge/CMakeLists.txt:41-137`; `bridge/aegis_bridge_ctypes.py` โหลด DLL ตาม platform และมี exported helper สำหรับ event/DEFCON/IPS. ส่วน Go nose และ Rust mouth เป็น process แยก โดย batch scripts เป็นตัว launch/stop แบบ legacy. Python `tools/aegisctl.py` เป็น control client ผ่าน named pipe ไม่ควรถูกถือเป็น enforcement provider

Boundary privilege จึงมีอย่างน้อยสี่ชั้น: (1) PowerShell/BAT/NSIS ที่ต้อง elevated สำหรับ service, driver และ HKLM; (2) kernel driver/WFP; (3) user-mode C/C++/Zig/Rust/Go process; และ (4) Python control/packaging layer. ปัจจุบันไม่พบหลักฐานที่ทำให้ transition ระหว่างชั้นเหล่านี้เป็น least privilege และตรวจ caller identity อย่างสม่ำเสมอ โดยเฉพาะ device ACL และ driver IOCTL

### 3. Package/install flow

`scripts/package_release.ps1:11-82` ใช้ timestamp ปัจจุบันสร้าง `release/aegis-nids-windows-$Version-$stamp`, copy binary จาก `zig-out`, config จาก `configs`, และ driver จาก `drivers\wfp_callout\aegis_wfp.sys`, คำนวณ SHA-256 และ zip. `release/.../manifest.json:1-54` เป็น manifest ของ bundle รุ่น 6.0.0 และตรวจ hash/size ของ runtime binary, config และ driver

ตัวติดตั้งใน release (`release/.../scripts/install_aegis.ps1:28-57`) ตรวจ artifact hash ก่อน stop process/service, ย้าย install tree เดิมไป `.backup`, copy bundle, และสร้าง service `AegisWfp` แบบ demand-start. มันไม่ start driver, ไม่ติดตั้งหรือ start `AegisNids`, ไม่ตรวจ signature และไม่ verify health หลัง copy. README ของ bundle (`release/.../README.txt:5-12`) จึงบอกวิธีติดตั้ง/rollback แต่ไม่ได้แสดง post-install evidence

เส้นทาง NSIS `installer/aegis.nsi:40-120` เป็นคนละ package model. มัน hard-code input จาก `config`, `zig-out`, `target/release`, `build/Release`, `go/aggregator` แล้วสร้าง service `AegisNids`, แต่ไม่ได้ package `aegis_wfp.sys` หรือสร้าง `AegisWfp`. `installer.nsi:19-109` เป็นอีก script ที่ package source snapshot และ driver source แทน runtime binary. ทั้งสองตัวมี version/path/behavior ต่างกัน และไม่มี selector ที่บังคับว่า release ต้องใช้ตัวใด

## Critical findings

### C-01 — Release/install pipeline แตกเป็นหลาย contract และไม่ติดตั้ง runtime ครบ

**หลักฐาน:** `scripts/package_release.ps1:21-30`, `release/.../manifest.json:7-52`, `release/.../scripts/install_aegis.ps1:45-57`, `installer/aegis.nsi:48-73`, `installer.nsi:19-108`

`package_release.ps1` ต้องการ driver ที่ `drivers\wfp_callout\aegis_wfp.sys` ซึ่งไม่ใช่ output ของ `wdk_build_production.ps1` และไม่ใช่ canonical output ของ `build_drivers.bat`. Bundle installer สร้าง/ตรวจเพียง service `AegisWfp`, แต่ไม่ start core หรือ register `AegisNids`. NSIS ใน `installer/aegis.nsi` กลับสร้างเฉพาะ `AegisNids` และไม่ package driver. `installer.nsi` ยัง package source snapshot และใช้ path ที่ไม่มีใน repository หลายรายการ. ผลคือชื่อว่า package สร้างสำเร็จอาจไม่ได้หมายความว่า host ได้ runtime และ driver ที่สอดคล้องกัน

**ผลกระทบ:** fresh install อาจได้ driver โดยไม่มี core, ได้ core โดยไม่มี driver, หรือ build/package หยุดที่ missing input. Upgrade ที่ใช้คนละ entrypoint สามารถเปลี่ยน service topology โดยไม่ตั้งใจ

**การแก้:** ประกาศ pipeline เดียวที่มี artifact graph เดียว. ให้ build ผลิต artifact ใน staging directory เดียว, ให้ package consume staging เท่านั้น, ให้ installer ติดตั้ง service/driver ตาม manifest เดียวกัน และเพิ่ม preflight ที่ fail หาก required artifact, service name, binary path หรือ protocol version ไม่ตรงกัน. ปิดการใช้งาน NSIS/Batch รุ่นเก่าหรือระบุชัดว่า lab-only

### C-02 — Production signing ไม่ได้ถูกบังคับ; signing path เป็น test signing และมี secret แบบ hard-coded

**หลักฐาน:** `scripts/wfp_sign.ps1:1-15`, `82-125`, `128-147`; `scripts/install_drivers.bat:100-167`; `scripts/wfp_service.ps1:41-62`; `scripts/verify_release.ps1:42-54`

`wfp_sign.ps1` ระบุเองว่าเป็น development path, สร้าง self-signed certificate, ใช้ default PFX password `aegis-test-2026`, export ไป `%TEMP%`, และหาก signature ไม่ valid จะ import certificate เข้า `LocalMachine\Root` และ `TrustedPublisher` (`wfp_sign.ps1:82-125`). `install_drivers.bat` เปิด `bcdedit /set testsigning on` และยอมเดินต่อเมื่อ `signtool` หาย (`install_drivers.bat:100-123`, `153-167`). `wfp_service.ps1` เพียง log `Get-AuthenticodeSignature` และยังเตือนว่า unsigned driver สามารถเดินต่อได้หากเปิด test signing (`wfp_service.ps1:47-62`). ไม่มี production script ที่ต้องใช้ certificate chain/EV/attestation/WHQL, timestamp ที่ตรวจสอบได้, catalog, thumbprint allow-list หรือ verify PE/driver ทุกไฟล์ใน bundle

**ผลกระทบ:** artifact ที่ถูกเรียกว่า production bundle อาจเป็น test-signed/unsigned และ host อาจถูกเปลี่ยน boot policy หรือ trust store. Password ที่อยู่ใน source ใช้ซ้ำได้และไม่เป็น secret management

**การแก้:** แยก `lab-sign.ps1` ออกจาก `release-sign.ps1` อย่างเด็ดขาด. Production gate ต้อง reject self-signed issuer, reject test mode, ตรวจ signature chain และ catalog ของ `.sys`, ตรวจ Authenticode ของ `.exe/.dll`, pin expected publisher/certificate policy และเก็บ signing operation evidence โดยไม่ใส่ private key/password ใน repository. Lab bundle ต้องมีชื่อ/metadata/installer UX ที่ระบุว่าใช้กับ test VM เท่านั้น

### C-03 — Device/IOCTL privilege boundary ไม่มีหลักฐาน ACL และเปิด operation ที่มีผลต่อ WFP

**หลักฐาน:** `drivers/wfp_callout/aegis_wfp.c:59-80`, `drivers/wfp_callout/aegis_wfp.h:22-26`, `drivers/wfp_callout/aegis_wfp.c:214-275`, `drivers/wfp_callout/aegis_wfp_comm.c:67-142`

Driver สร้าง device ด้วย `IoCreateDevice` และไม่ใช้ `IoCreateDeviceSecure` หรือ SDDL (`aegis_wfp.c:59-63`). `AegisWfpCreate` อนุญาตทุก open (`aegis_wfp.c:132-149`). Header ประกาศ IOCTL block/unblock ด้วย `FILE_WRITE_DATA` แต่ไม่มี code-side caller authorization หรือ policy check (`aegis_wfp.h:22-26`). Block path เพิ่ม filter ด้วย `FWPM_FILTER_FLAG_PERSISTENT` (`aegis_wfp.c:256-275`). ดังนั้นจากโค้ดที่ตรวจยังไม่มีหลักฐานว่าการเปิด device ถูกจำกัดเฉพาะ service identity/administrator หรือว่าการเรียก mutation ต้องผ่าน provider ที่ตรวจสิทธิ์

**ผลกระทบ:** caller ที่เปิด device ได้อาจเรียก privileged IOCTL โดย bypass control-plane boundary. แม้จะไม่สรุปว่า block สำเร็จบน host แต่ surface นี้เป็น security boundary ที่ต้องปิดก่อน production

**การแก้:** กำหนด device SDDL แบบ least privilege, ตรวจ caller token/บริการที่อนุญาตในทุก mutation, แยก read-only device กับ privileged provider channel, เพิ่ม audit receipt ที่ผูก request/identity/filter ID และทำ negative tests จาก standard user/service account ที่ไม่ควรได้สิทธิ์

### C-04 — Persistent WFP filter ไม่ถูกจัดการแบบ transaction และ uninstall อาจทิ้ง residual policy

**หลักฐาน:** `drivers/wfp_callout/aegis_wfp.c:256-275`, `355-409`; `drivers/wfp_callout/aegis_wfp_callout.c:236-264`; `scripts/wfp_service.ps1:106-121`; `scripts/install_aegis.ps1:39-52`

`AegisWfpBlockFlow` สร้าง persistent filter แต่เก็บเพียง filter ID ล่าสุดไว้ใน global `g_FilterId`. ทุกคำขอใหม่สามารถ overwrite ID เดิม (`aegis_wfp.c:266-273`). Unload ลบ filter ที่ global ชี้อยู่เท่านั้น และใน `AegisWfpUnregisterCallout` ตั้ง `g_CalloutId = 0` ก่อนถึง branch ที่จะลบ BFE callout (`aegis_wfp_callout.c:239-258`), จึงไม่มีหลักฐานว่า callout/filter ทั้งหมดจะถูกลบครบ. Service uninstall ลบ service และไฟล์เท่านั้น (`wfp_service.ps1:106-121`) และ release installer ก็เช่นเดียวกัน

**ผลกระทบ:** upgrade/rollback/uninstall อาจเหลือ persistent WFP state จากรุ่นก่อน ทำให้ behavior ไม่ตรงกับ installed manifest และทำให้ recovery ยาก. นี่เป็น lifecycle/security defect แม้ไม่ใช้ residual filter เป็นหลักฐานว่า enforcement path ใช้งานได้

**การแก้:** ทำ registry ของ filter ID ทั้งหมดแบบ synchronized และกำหนด owner/provider key ที่ค้นคืนได้จาก BFE. ใช้ dynamic session หาก policy ต้อง ephemeral หรือทำ explicit delete ทุก persistent object ก่อน service removal. Installer rollback ต้องตรวจ zero residual AEGIS filters และ fail-closed หาก cleanup ไม่สำเร็จ

### C-05 — Upgrade/rollback ไม่ atomic และ rollback ที่เขียนไว้ไม่ใช่ recovery transaction

**หลักฐาน:** `release/.../scripts/install_aegis.ps1:19-25`, `39-57`; `scripts/wfp_service.ps1:64-83`, `106-121`; `installer/aegis.nsi:105-119`

Release installer ลบ backup เดิม, ย้าย install tree ไป `.backup`, สร้าง directory ใหม่ และ copy (`install_aegis.ps1:39-43`). หากขั้นตอนหลังจากนั้นล้มเหลว ไม่มี `try/catch` ที่ย้าย backup กลับ. Rollback ลบ install tree ปัจจุบันแล้ว `Move-Item` backup กลับ (`install_aegis.ps1:19-25`) แต่ไม่ recreate/update service, ไม่ restore driver load state, ไม่ verify manifest/signature, ไม่ verify health และไม่มี protection ต่อ interruption ระหว่าง remove/move. ใน `wfp_service.ps1`, `Fail` เรียก `exit 1` ก่อนบรรทัดลบ binary ที่เขียนเป็น rollback (`wfp_service.ps1:77-81`), ทำให้ rollback branch นั้น dead code. Existing service ถูกลบก่อน copy driver ใหม่ (`wfp_service.ps1:64-73`) จึงมี outage window และอาจเสียของเดิมถ้า create ใหม่ล้มเหลว

**ผลกระทบ:** failed upgrade อาจทิ้ง host ที่ไม่มี service/driver หรือ rollback แล้วได้ tree แต่ไม่มี service ที่ใช้งาน. ไม่มี RPO/RTO ที่วัดจาก Windows host

**การแก้:** ใช้ staged install ใน sibling directory, validate ทั้ง tree, stop service ด้วย bounded wait, atomic rename/swap, เก็บ service configuration เดิม, commit marker และ rollback journal. ทุก failure ต้อง execute compensating action และตรวจ postcondition: manifest/hash/signature, service config, driver state, no residual filter, core health

### C-06 — Active WFP ABI ระหว่าง kernel, C helper และ Zig ไม่ตรงกัน

**หลักฐาน:** `drivers/wfp_callout/aegis_wfp.h:79-89`; `drivers/wfp_callout/aegis_wfp.c:277-352`; `src/windows/wfp_ioctl.c:61-69`, `153-161`; `src/policy/wfp_ioctl.zig:54-60`, `205-225`

Kernel header ประกาศ `AEGIS_RING_STATS` ขนาด 24 bytes และ `AegisWfpGetStats` reject output buffer ที่เล็กกว่า 24 bytes (`aegis_wfp.c:277-283`). C user helper ก็ประกาศ 6 `uint32_t` รวม 24 bytes (`src/windows/wfp_ioctl.c:61-69`). แต่ Zig binding ประกาศ `WfpRingStats` เพียง 4 fields รวม 16 bytes และส่ง `@sizeOf(WfpRingStats)` ไปยัง driver (`src/policy/wfp_ioctl.zig:54-60`, `205-225`). เส้นทาง canonical Zig จึงถูก driver ตอบ `STATUS_BUFFER_TOO_SMALL` ตามโค้ดที่อ่าน

นอกจากนี้ C helper รุ่นเก่ายังส่ง IPv4 4 bytes ให้ `IOCTL_AEGIS_BLOCK_FLOW` (`src/windows/wfp_ioctl.c:107-117`) ขณะที่ kernel implementation ใน `aegis_wfp.c:228-234` ต้องการ `AEGIS_WFP_FLOW_REQUEST` อย่างน้อย 8 bytes และ response 12 bytes. แม้ส่วนนี้ไม่ถูกใช้เป็นหลักฐาน enforcement ในรายงาน แต่เป็น ABI drift ที่ทำให้ caller รุ่นเก่าและ driver รุ่นใหม่สื่อสารกันไม่ได้

**การแก้:** กำหนด wire header/ABI เดียวใน `shared/abi` หรือ generated C/Zig bindings, assert size/offset/IOCTL constants ใน C, Zig และ Windows integration test, เพิ่ม version field และ reject mismatch ก่อนเปิด service. ลบ duplicate legacy implementation หรือประกาศ owner ของแต่ละ IOCTL ให้ชัดเจน

## Important findings

### I-01 — Toolchain discovery ไม่ reproducible และ WDK/MSVC path มีสองมาตรฐาน

**หลักฐาน:** `scripts/wdk_build_production.ps1:23-52`, `55-169`; `scripts/build_drivers.bat:87-125`, `162-210`; `Makefile:5-19`

PowerShell เลือก `vswhere -latest` และ directory MSVC ล่าสุด; WDK ก็เลือก version ล่าสุดที่มี library. ไม่มี lock ของ exact VS instance, MSVC toolset, Windows SDK/WDK build, include/lib hash หรือ environment snapshot. Batch ตรวจ path `C:\Progra~2\Windows Kits\11` และ hard-code Visual Studio 2022 Enterprise (`build_drivers.bat:95-109`, `166-168`) จึงไม่ครอบคลุม Build Tools/Community และ WDK 11 branch ไม่เติม `WDK_VERSION`, `WDK_INCLUDE` หรือ `WDK_LIB` ให้ครบ. Batch ยังเลือก `where cl.exe` และ `where link.exe` แยกกัน ซึ่งอาจมาจาก toolset คนละชุด

**ผลกระทบ:** source เดียวกันอาจได้ driver ABI/binary ต่างกันหรือ build ไม่ได้ตามเครื่อง. `Makefile all` ก็ไม่รวม driver gate

**การแก้:** ใช้ toolchain manifest ที่ pin exact versions/path hashes, ใช้ `vswhere`/WDK discovery implementation เดียว, export environment และ compiler command line ลง provenance. เพิ่ม clean-room Windows CI ที่สร้างจาก fresh checkout

### I-02 — Build flags และ artifact selection แยก lab/debug กับ release ไม่ชัด

**หลักฐาน:** `scripts/build_and_check.ps1:22-35`, `scripts/wdk_build_production.ps1:220-255`, `scripts/build_drivers.bat:184-210`, `installer/aegis.nsi:53-65`

`build_and_check.ps1` สร้าง core ด้วย `-ODebug`; driver PowerShell ใช้ `/O2` แต่ `/GS-`; batch ใช้ flags/defines คนละชุด (`NDIS60` เทียบกับ `NDIS630`, `/MERGE` และ `/INTEGRITYCHECK` ต่างกัน). NSIS ดึง binary จากทั้ง `zig-out`, `target/release` และ `build/Release` โดยไม่ตรวจว่าเป็น configuration เดียวกัน

**การแก้:** แยก `lab-debug`, `test-signed-lab` และ `production-release` เป็น profiles ที่มี flags, dependencies, signing policy และ output directory ชัดเจน. ห้าม production profile ใช้ `/GS-` โดยไม่มี security review ที่เป็นลายลักษณ์อักษร

### I-03 — Manifest/provenance ครอบคลุม source บางส่วน แต่ไม่ครอบคลุม Windows driver และ binary provenance

**หลักฐาน:** `tools/release_engineering.py:70-112`, `137-198`, `281-308`; `build_manifest.json:1-20`; `release/.../manifest.json:1-52`

`build_manifest.json` ระบุ source commit และภาษา แต่ `collect_artifacts()` เดิน `core`, `shield`, `scripts`, `tools`, `installer`, `go`, `brain`, `ts_policy`, `bridge` (`release_engineering.py:79-112`) และไม่เดิน `src/windows`, `drivers`, `Makefile` หรือ `mouth/nose` ตามที่ release path ใช้จริง. การตรวจ manifest ข้าม artifact ที่ไม่มีอยู่ (`verify_manifest:292-300`) และยังพิมพ์ `OK` ถ้า artifact ที่มีอยู่ไม่ drift แม้มี missing จำนวนมาก. `--package` สร้าง zip จาก source artifacts ไม่ใช่ runtime bundle ที่ installer ใช้ (`release_engineering.py:388-402`)

ใน working tree ปัจจุบัน manifest bundle รุ่น 6.0.0 มี hash ตรงกับ binary ที่อยู่ใน release directory แต่ binary 7 รายการนั้นไม่ tracked. `build_manifest.json` เป็น version 5.0.0 และ release manifest เป็น 6.0.0; NSIS มี 5.0.0 และ top-level `installer.nsi` มี 1.0.0. Commit ใน NSIS คือ `0c74e3f`, ขณะที่ `git rev-parse --short HEAD` ที่ตรวจได้คือ `46b93dc`. นี่เป็น provenance contradiction ไม่ใช่เพียง formatting

**การแก้:** มี manifest เดียวที่แยก `source inputs`, `built artifacts`, `package members`, `signatures` และ `toolchain`. Missing required artifact ต้อง fail. บันทึก exact commit/tree state, WDK/MSVC versions, command lines, input hashes และ signature metadata. ให้ version/commit จาก source เดียว ไม่ hard-code หลายจุด

### I-04 — ZIP/package ไม่ deterministic และ SBOM ID เปลี่ยนได้ตาม Python hash seed

**หลักฐาน:** `scripts/package_release.ps1:11-13`, `50-58`, `78-82`; `scripts/release_package.ps1:131-155`; `tools/release_engineering.py:249-277`, `388-402`

ชื่อ bundle และ `created_utc` ใช้เวลาปัจจุบัน. `release_package.ps1` บันทึก build date ปัจจุบันและใช้ `Compress-Archive`; ไม่มี `SOURCE_DATE_EPOCH`, canonical ordering หรือ normalized timestamps. `release_engineering.py` สร้าง SPDXID ด้วย built-in `hash(art['path'])` (`release_engineering.py:253-264`) ซึ่งเปลี่ยนตาม `PYTHONHASHSEED` และจึงไม่ reproducible. ไม่มีการ verify byte-for-byte archive จาก clean rebuild

**การแก้:** ใช้ deterministic archive writer, sort path, normalize metadata/time, derive release timestamp จาก commit/explicit parameter และใช้ SHA-256 ของ path สำหรับ SPDXID. เพิ่ม reproducibility test ที่ build สองครั้งบน clean Windows runner แล้วเปรียบเทียบ manifest/package hash

### I-05 — Release verification เป็น existence check และ optional hash check ไม่ใช่ release gate

**หลักฐาน:** `scripts/verify_release.ps1:16-18`, `42-54`, `65-112`; `scripts/release_package.ps1:62-149`

`verify_release.ps1` ตั้ง `$ErrorActionPreference = 'Continue'` และถ้าไฟล์ `.sha256` หายจะข้าม hash verification (`42-54`). หลัง extract จะตรวจเพียง required paths, manifest JSON และ binary มีอยู่ (`65-112`), ไม่ recompute hash ของทุก package member, ไม่ตรวจ Authenticode/catalog, ไม่ตรวจ architecture/imports, ไม่ตรวจ service/driver metadata และไม่ตรวจ runtime health. นอกจากนี้ expected layout เป็น `bin/`, `configs/`, `build.zig`, `src/release_info.zig` ซึ่งไม่ตรงกับ bundle ที่ `package_release.ps1` สร้างเป็น `runtime/`, `drivers/`, `configs/`

**การแก้:** ทำ verifier ที่อ่าน manifest เป็น authority, fail closed เมื่อ hash sidecar หาย, ตรวจทุก file/size/hash/signature/catalog/PE architecture/service contract และต้องตรวจ package layout เดียวกับ installer. ห้ามใช้ “binary exists” เป็น runnable evidence

### I-06 — NSIS generator ไม่ได้สร้าง directives จาก manifest ตามที่อ้าง และ input บางตัวไม่มีจริง

**หลักฐาน:** `tools/installer.py:18-35`, `37-103`, `106-139`; `tests/release/test_t17_perf_ci_installer.py:216-252`; `installer/aegis.nsi:1-18`

`tools/installer.py` โหลด `components` เพียงเพื่อเขียน comment (`installer.py:106-115`); `file_directive()` ไม่ถูกใช้สร้าง payload. NSIS template hard-code binary names, commit `2c7cb30`, paths `config\Rules.json`, `configs\trust_store`, และ source snapshot ไม่ได้ map จาก artifact path/hash ใน manifest. `installer/aegis.nsi` ใช้ `${OUTPUT}` ที่ไม่ได้กำหนดในไฟล์ และต้องการ `LICENSE.txt` กับ `aegis_runtime_stamp.txt` ซึ่งไม่พบใน repository ที่ตรวจ. Top-level `installer.nsi` ก็อ้าง source names เช่น `nids_main.zig`, `windows_brain.py`, `go.mod` ที่ไม่มีตาม path นั้น

Test T17 ตรวจเพียง string และ generator return code ไม่ได้เรียก `makensis` (`test_t17_perf_ci_installer.py:241-252`)

**การแก้:** สร้าง NSIS directives จาก resolved manifest โดยตรง, reject missing input และ path นอก staging root, compile ด้วย `makensis` ใน CI และ install/uninstall ใน Windows VM. ลบ template ที่ stale หรือ mark เป็น historical

### I-07 — Bundle installer ไม่ update existing service และไม่ verify post-install state

**หลักฐาน:** `release/.../scripts/install_aegis.ps1:45-57`

ตัวติดตั้ง query `AegisWfp` แล้วสร้างใหม่เฉพาะเมื่อไม่มี service (`47-52`). หาก service มีอยู่แต่ชี้ binary/path/config เก่า จะไม่ update. มันไม่ตรวจ `sc create` exit code, ไม่ตรวจ service `binPath`, ไม่ start driver/core และไม่ตรวจ signature หลัง copy. `??\$driver` ถูกสร้างจาก path ที่อาจมีช่องว่าง เช่น `C:\Program Files\...` โดยไม่มีการพิสูจน์ว่า quoting ที่ส่งให้ `sc.exe` ถูกต้องในทุก path (`51`)

**การแก้:** ใช้ `sc.exe` argument array หรือ native Service Control API ที่ไม่พึ่ง parser แบบ `sc`, validate/repair existing service, quote path ที่มี space, ตรวจ return code ทุก command และ run postcondition checks

### I-08 — `wfp_service.ps1` fail-soft และ cleanup concurrency ไม่ปลอดภัย

**หลักฐาน:** `scripts/wfp_service.ps1:24-32`, `64-83`, `86-121`, `124-151`

`$ErrorActionPreference = 'Continue'` ทำให้ command error หลายตัวไม่หยุด flow. `Stop-Driver` เตือนแต่ยังคืน success (`98-104`), uninstall ไม่รอให้ service stop จริงก่อนลบ file (`113-121`), และจบด้วย `exit 0` เสมอ (`144-151`). การตรวจ signature แค่ log status และไม่ reject invalid status (`41-62`).

**การแก้:** ใช้ fail-closed, ตรวจ `$LASTEXITCODE` ทุก SCM operation, wait ตาม state transition พร้อม timeout, ไม่ลบ loaded driver, ใช้ retry/rollback และ return non-zero เมื่อ postcondition ไม่ผ่าน

### I-09 — FIM native helper มี race และ use-after-free เมื่อ stop timeout

**หลักฐาน:** `src/windows/fim_native.c:26-54`, `57-93`, `97-125`

Thread อ่าน `s->data_ready` นอก critical section (`30`), ขณะที่ poll เขียนภายใต้ lock. `CreateEvent` เป็น manual-reset และไม่ reset ก่อน reuse (`74`, `33-43`), ทำให้ wait อาจถูก signal ค้าง. `aegis_fim_stop` เรียก `CancelIoEx`, รอ thread เพียง 5 วินาที แล้วปิด handles/delete critical section/free session โดยไม่ตรวจว่า `WaitForSingleObject` ได้ `WAIT_OBJECT_0` (`100-107`). Thread ที่ยังทำงานต่อจะ dereference freed `s`. `MultiByteToWideChar` ไม่ตรวจ return/overflow ของ fixed `MAX_PATH` buffer (`57-60`)

**การแก้:** ใช้ event lifecycle ที่ reset ถูกต้องหรือ I/O completion port, lock ทุก shared state, stop ต้อง wait สำเร็จหรือไม่ free memory จน thread exit, รองรับ long path และตรวจ conversion result. เพิ่ม stress test start/stop/poll พร้อม cancellation และ path ยาว

### I-10 — Driver ring buffer/statistics correctness ยังไม่มีหลักฐานเพียงพอ

**หลักฐาน:** `drivers/wfp_callout/aegis_wfp.h:49-57`, `79-89`; `drivers/wfp_callout/aegis_wfp_callout.c:83-109`; `drivers/wfp_callout/aegis_wfp.c:181-212`, `277-352`

Ring buffer ใช้ write/read offset ที่มี empty/full ambiguity เมื่อ write offset wrap กลับเท่ากับ read offset (`AEGIS_RING_USED()`), และเมื่อเต็มจะ drop event แต่ไม่เพิ่ม `totalDrops`. `AEGIS_RING_STATS` fields ส่วนใหญ่ไม่ถูก increment. `AegisWfpGetStats` เปิด WFP engine และ enumerate เพียงหนึ่ง filter (`aegis_wfp.c:322-347`) จึงไม่ใช่ ring stats ตามชื่อ struct และอาจรายงาน count ไม่ครบ

**การแก้:** ใช้ monotonic sequence/explicit full bit, update counters แบบ atomic/lock-protected, แยก API `ring_stats` กับ `filter_stats`, กำหนด overflow policy และทดสอบ wrap/full/consumer ช้าด้วย kernel/user integration test

### I-11 — Batch install เปิด test mode และ fallback signing โดยไม่ทำ atomic rollback

**หลักฐาน:** `scripts/install_drivers.bat:100-149`, `153-229`, `243-264`

หาก testsigning ไม่เปิด script จะเปลี่ยน BCD และออกให้ reboot (`100-123`). `makecert`/PowerShell fallback อาจสร้าง cert คนละ store กับ `signtool /s TrustedPeople` (`131-149`). ถ้า `netcfg` ล้มเหลว script fallback ไป `sc create` และอาจ start service แต่ไม่มี undo เมื่อ minifilter ขั้นถัดไปล้มเหลว (`169-226`). Uninstall ลบ service แต่ระบุเองว่า testsigning ยังคงเปิด (`243-264`)

**การแก้:** แยก lab install, บันทึก pre-state แล้ว restore BCD/trust store เมื่อ cleanup, verify cert store/thumbprint/signature ก่อน install, และทำ transaction ระหว่าง WFP/minifilter install

### I-12 — Legacy process control ใช้ global process names และ force kill

**หลักฐาน:** `scripts/stop_aegis.bat:10-27`, `scripts/run_aegis.bat:118-145`, `scripts/clean_aegis.bat:60-86`, `installer.nsi:111-145`

Fallback stop/cleanup ใช้ `taskkill /IM` กับชื่อทั่วไป เช่น `python.exe` ใน NSIS (`installer.nsi:112-114`) และ force kill process โดยไม่ผูก PID, install root หรือ service identity. `clean_aegis.bat` ยังพยายาม `takeown`, `icacls Everyone:F` และ restart Explorer (`clean_aegis.bat:122-155`). แม้เป็น tooling cleanup แต่ privilege boundary และ blast radius สูง

**การแก้:** ใช้ service/process handles ที่สร้างโดย installer, เก็บ PID พร้อม owner/start time, ไม่ kill `python.exe` ทั้งเครื่อง, ไม่ grant `Everyone:F`, และห้าม cleanup production data/logs โดย default

### I-13 — Version/config/protocol identity กระจัดกระจาย

**หลักฐาน:** `installer.nsi:5-12`; `installer/aegis.nsi:5-24`, `81-86`; `tools/installer.py:37-46`; `build_manifest.json:1-20`; `release/.../manifest.json:1-6`; `scripts/release_package.ps1:24-47`

พบ version 1.0.0, 5.0.0, 6.0.0 และ commit หลายค่าใน tracked paths. `release_package.ps1` ยังอ่าน `src\release_info.zig` ที่ไม่มีอยู่ตาม path ที่ตรวจ (`release_package.ps1:24-31`). ไม่มี invariant ที่บังคับว่า installer display version, service metadata, manifest version, binary version และ protocol/ABI version ต้องตรงกัน

**การแก้:** สร้าง version artifact เดียวจาก commit/tag, inject เข้า build/package/NSIS/service registry, ตรวจ ABI/protocol compatibility ก่อน packaging และ reject mixed-version tree

## Test และ evidence gaps

1. ไม่มี tracked `build/**/*` และไม่มี clean Windows build evidence ใน repository. สิ่งที่เรียกว่า build output ใน `release/` ไม่ได้อยู่ใน git index แม้ hash ใน release manifest ตรงกับไฟล์ที่มีอยู่ใน working treeก็ตาม

2. `tests/release/test_t17_perf_ci_installer.py` เป็น structural/source-text gate เป็นหลัก. การทดสอบ Zig ใน `test_ac1_perf_zig_gates_green` รัน `python -c pass` (`test_t17_perf_ci_installer.py:74-82`) ไม่ใช่ Zig build. Generator test ไม่เรียก `makensis` (`241-252`) และ rollback test เรียก tooling บน checkout ซึ่งไม่ได้พิสูจน์ Windows service/driver rollback

3. ไม่พบ test ที่ติดตั้ง/ถอน service จริง, ตรวจ `sc.exe` state transition, verify driver loaded/unloaded, ตรวจ no residual WFP filters, หรือ validate upgrade interruption ระหว่าง copy/move. `scripts/windows_host_verification.py:34-169` อธิบายลำดับ Build→Package→Sign→Install→Load→Register→Enforce→Observe→Rollback แต่ไฟล์นี้พิมพ์ checklist และระบุว่าการพิสูจน์จริงต้องใช้ host; ไม่ใช่ test execution evidence

4. ไม่มี test ของ WDK/MSVC discovery เมื่อมี Visual Studio หลาย instance, Build Tools/Community, WDK 10/11, missing `fwpmk.lib`, path ที่มี space, non-English locale หรือ mismatched `cl`/`link` environment.

5. ไม่มี signature gate สำหรับ `.sys`, `.exe`, `.dll`, catalog/chain/issuer/expiry/timestamp และไม่มี negative test ที่ production profile ปฏิเสธ self-signed/test-signed artifact หรือ host test mode.

6. ไม่มี ABI contract test ที่ compile/size-check `AEGIS_RING_STATS`, `AEGIS_WFP_FLOW_REQUEST/RESPONSE`, event header และ IOCTL constants พร้อมกันระหว่าง kernel C, user C และ Zig. ปัจจุบัน static review พบ stats 24-byte vs 16-byte mismatch แล้ว

7. ไม่มี concurrency/stress test สำหรับ FIM cancellation, repeated start/stop, event signal reuse, long path, ring full/wrap, concurrent IOCTL และ process shutdown. การอ่าน/เขียน shared state ใน FIM ยังไม่ถูกพิสูจน์ด้วย race detector หรือ Windows stress harness

8. ไม่มี test ของ installer path traversal/manifest tampering, missing sidecar hash, stale service repair, interrupted copy, backup collision, rollback failure และ data-preservation policy. `verify_release.ps1` ยังข้าม hash หาก sidecar ไม่อยู่

9. ไม่มี reproducibility test ที่สร้างจาก clean checkout สองครั้งแล้วเปรียบเทียบ binary/package/SBOM. Timestamp ปัจจุบันและ Python built-in `hash()` ทำให้ผลไม่ deterministic โดย design

10. ไม่มีหลักฐานว่า lab-vs-production separation ถูก enforce ทางโค้ด. ปัจจุบัน production-looking README ใช้ installer ที่เรียก test-signing tooling ได้ และไม่มี release gate ที่ reject development certificate

## Recommended actions ตามลำดับความสำคัญ

### P0 — ก่อนเรียกใช้ production

1. **Freeze release path เดียว:** ระบุ canonical build graph, staging layout, manifest schema, installer และ service topology เดียว. ลบหรือ mark stale `installer.nsi`, batch release path และ PowerShell path ที่ไม่ใช่ canonical. Required artifact missing ต้อง fail

2. **ปิดช่อง privilege boundary:** เพิ่ม explicit device ACL/SDDL, แยก telemetry read-only จาก privileged mutation, ตรวจ caller/service identity และเพิ่ม negative tests จาก standard user. ทำ audit receipt ของ privileged operation

3. **แก้ persistent WFP lifecycle:** เก็บ filter IDs ทั้งหมด, owner/provider key, explicit delete/rollback และตรวจ residual state ก่อน uninstall/upgrade สำเร็จ. ห้ามลบ driver file หรือรายงาน success หาก filter cleanup ไม่ผ่าน

4. **แยก signing lab กับ production:** ย้าย self-signed/password/testsigning ไปไฟล์และ profile ที่ตั้งชื่อ lab ชัดเจน. Production pipeline ต้องตรวจ Authenticode/catalog/issuer/chain/timestamp และ fail เมื่อพบ self-signed, unsigned หรือ test mode

5. **ทำ installer transaction:** stage → validate → stop/wait → swap → configure service → start/health-check → commit. เก็บ journal และ compensating rollback ที่ restore tree, service configuration, driver state และ config/data แบบ bounded และ observable

6. **แก้ ABI ก่อน deploy:** สร้าง generated/shared ABI ที่เป็น authority และ size/offset/IOCTL tests ระหว่าง kernel C, user C และ Zig. โดยเฉพาะ `WfpRingStats` 16/24-byte mismatch และ old 4-byte block request ต้องถูกลบหรือ versioned

### P1 — ทำให้ build/release เชื่อถือได้

7. Pin exact VS/MSVC/Windows SDK/WDK/Zig/Rust/Go/Node/Python versions และ hash/toolchain inventory. ใช้ discovery code เดียว ไม่เลือก `-latest` แบบ implicit และบันทึก command line/environment ใน provenance

8. ทำ deterministic build/package: explicit source revision/time, sorted archive entries, normalized timestamps, deterministic SBOM IDs, no current-time-only identity และ clean-room rebuild comparison

9. เปลี่ยน verifier ให้ fail closed: manifest เป็น authority, ตรวจทุก file/size/hash/signature/catalog/architecture/dependency, reject missing sidecar, reject extra/unlisted files และ validate package layout เดียวกับ installer

10. ทำ Windows VM CI สำหรับ `makensis`, fresh install, upgrade, interrupted upgrade, rollback, service repair, driver install/load/unload, no-residual-filter และ data preservation. ห้ามถือ source-string assertions เป็น runtime evidence

11. เพิ่ม failure-injection tests ของ `sc`, `Copy-Item`, `Move-Item`, `signtool`, `Fwpm*`, service stop timeout และ disk-full/locked-file cases. ทุก failure ต้องมี exit code, log และ recovery postcondition

### P2 — Reliability และ maintenance

12. แก้ FIM native helper ให้ stop รอ thread จบจริง, lock shared state, reset event ถูกต้อง, ตรวจ conversion/path length และเพิ่ม start/stop stress test

13. แก้ ring buffer/stat counters ให้มี overflow semantics ที่ชัดเจนและ metrics ที่ตรงกับ API name. ทดสอบ wrap/full/slow consumer และ concurrent reader/writer

14. ลด blast radius ของ legacy BAT cleanup/stop: ไม่ใช้ global `taskkill`, ไม่แก้ ACL เป็น `Everyone:F`, ไม่ kill `python.exe` ทั้งเครื่อง และให้ installer เป็นเจ้าของ process/service identity

15. รวม version/commit/protocol/ABI metadata จาก source เดียวและเพิ่ม gate ว่า release manifest, NSIS metadata, service registry, binary version และ runtime protocol ต้องเป็นชุดเดียวกัน

## สถานะความเชื่อมั่น

สิ่งที่ยืนยันได้จากโค้ดคือมี implementation ของ WDK discovery, C kernel driver, user-mode IOCTL, FIM helper, CMake bridge, PowerShell/BAT install scripts, NSIS templates และ SHA-256 manifest checks อยู่จริง. สิ่งที่ **ยังยืนยันไม่ได้** คือ production-grade signing, deterministic rebuild, complete installation, safe rollback, least-privilege device access, ABI compatibilityของทุกเส้นทาง และ Windows host evidence ที่แสดงว่าทั้ง package/service/driver/runtime เป็นชุดเดียวกัน. ดังนั้นไม่ควรประกาศ release นี้ว่า production-ready จนกว่า P0 และ evidence gaps ข้างต้นจะปิดด้วย executable Windows tests และ provenance ที่ตรวจย้อนกลับได้

## References

หลักฐานทั้งหมดมาจาก source-of-truth repository ที่ระบุในรายงานนี้. Inventory ที่ใช้ cross-check คือ `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/analysis/deep_audit/tracked_files.txt`; รายงานนี้ไม่พึ่งข้อมูลภายนอก repository และไม่ถือ handoff เป็นหลักฐานแทน source code

- Repository root: `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows`
- Tracked-file inventory: `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/analysis/deep_audit/tracked_files.txt`
- Relevant test contract: `tests/release/test_t17_perf_ci_installer.py`
- Windows host verification checklist: `scripts/windows_host_verification.py`
- Release manifest inspected: `release/aegis-nids-windows-6.0.0-20260916_223148/manifest.json`
- Build provenance inspected: `build_manifest.json`

*หมายเหตุ: ไม่มีไฟล์ใดถูกแก้ไขระหว่างการ audit นี้ นอกจากการสร้างรายงานฉบับนี้ใน `analysis/deep_audit/06-windows-scripts.md` ตามคำขอ*
