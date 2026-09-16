# AEGIS NIDS: สถานะระบบและ Roadmap ใหม่

**สถานะการประเมิน:** 16 กันยายน 2026  
**ขอบเขต:** Windows hybrid runtime, native telemetry, control plane, detection pipeline และ production readiness

## ข้อสรุป

AEGIS NIDS ผ่าน **Core Runtime Readiness** และ **Golden Path Readiness** แล้ว แต่ยังไม่ควรนำขึ้น Production ทันที ระบบควรเข้าสู่ **Pre-production Validation** ก่อน แล้วจึงทำ Controlled Attack Test ใน Lab ที่ได้รับอนุญาต หลังจากผ่าน recovery, deployment, security และ performance gates จึงค่อยพิจารณา Production rollout แบบจำกัดขอบเขต

เหตุผลคือผลล่าสุดยืนยันว่า runtime ทำงานครบและเส้นทางตรวจจับทำงานจริง แต่ยังไม่มีหลักฐานเพียงพอด้านการติดตั้งบนเครื่องใหม่ การ rollback การ restart recovery การรับโหลดต่อเนื่อง และการทดสอบ native failure ในสภาพแวดล้อม production

## สถานะที่ผ่านแล้ว

| พื้นที่ | หลักฐานล่าสุด | ผล |
|---|---|---|
| Core lifecycle | `State: RUNNING` | ผ่าน |
| Overall health | `Degraded: False` | ผ่าน |
| Subsystems | 7/7 subsystems running | ผ่าน |
| WFP | `wfp=true`, bridge เปิดใช้งาน | ผ่าน |
| C++ bridge | `cpp=true`, bridge ทำงาน | ผ่าน |
| ETW | `etw_ready: True` | ผ่าน |
| FIM | `fim_ready: True` | ผ่าน |
| Registry | `registry_ready: True` | ผ่าน |
| Worker failure state | `failure_mask: 0` | ผ่าน |
| Rules | `rules_loaded: 22` | ผ่าน |
| Event ingress | XSS fixture ส่งผ่าน named pipe สำเร็จ | ผ่าน |
| Detection | `detections` เพิ่มเป็น 2 | ผ่าน |
| Forensic | 30 records และ `integrity: ok` | ผ่าน |
| Control plane | `metrics.snapshot` และ `forensics.verify` สำเร็จ | ผ่าน |

## สิ่งที่ผลล่าสุดพิสูจน์ได้

ผลล่าสุดพิสูจน์ว่า event สามารถเข้าสู่ระบบผ่าน `aegis_sensor_pipe` ถูกประมวลผลโดย pipeline และสร้าง forensic record ที่ตรวจสอบ hash chain ได้ นอกจากนี้ XSS fixture ทำให้ detection counter เพิ่มขึ้นโดยไม่ทำให้ระบบ degraded

ค่าที่สำคัญจากผลล่าสุดคือ:

```text
State: RUNNING
Degraded: False
rules_loaded: 22
events_processed: 30
detections: 2
forensic_records: 30
errors: 0
failure_mask: 0
forensics integrity: ok
```

สิ่งนี้เพียงพอสำหรับการประกาศว่า **ระบบพร้อมเข้าสู่การทดสอบแบบควบคุม** แต่ยังไม่เพียงพอสำหรับการประกาศ Production-ready

## ส่วนที่ยังต้องพัฒนาและตรวจสอบ

### 1. Deployment และ portability

ต้องมีแพ็กเกจติดตั้งที่ระบุ binary, DLL, driver, configuration, service registration, runtime dependency และ version manifest ครบถ้วน การติดตั้งบนเครื่องทดสอบใหม่ต้องไม่พึ่งพา path ของเครื่องพัฒนา หรือ DLL ที่ค้างอยู่ใน `PATH`

ต้องเพิ่มการตรวจสอบดังต่อไปนี้:

- ตรวจ SHA-256 ของ artifact ทุกตัวก่อนติดตั้ง
- ตรวจ Windows architecture และ runtime prerequisite
- ติดตั้งและถอนการติดตั้ง service ได้อย่างสะอาด
- ตรวจ driver signature และ Code Integrity ก่อน start
- ตรวจว่า `configs\Rules.json` เป็น canonical path เพียงหนึ่งเดียว
- สร้าง uninstall และ rollback procedure

### 2. Lifecycle และ recovery

ต้องทดสอบการหยุดและเริ่มใหม่หลังจาก native workers ทำงานอยู่ รวมถึงการล้มเหลวของ WFP, ETW, FIM และ Registry ระหว่าง runtime ระบบต้องไม่รายงาน `READY` เมื่อ worker หยุด และต้องไม่ทิ้ง process, pipe, ETW session หรือ driver handle ค้าง

ต้องผ่านกรณีต่อไปนี้:

- core restart ปกติ
- power interruption simulation ใน Lab
- ETW session stale แล้วเริ่มใหม่
- FIM watcher หยุดและสร้างใหม่
- WFP service restart
- named pipe client disconnect ระหว่าง response
- rules reload หลายครั้งต่อเนื่อง

### 3. Control plane และ rules operations

ต้องทดสอบคำสั่ง Control Center ผ่าน public command surface ไม่ใช่การเรียก named pipe แบบ ad hoc คำสั่ง `rules.validate`, `rules.reload`, `metrics.snapshot` และ `forensics.verify` ต้องให้ผลสำเร็จและมี response ที่ parse ได้ทุกครั้ง

ต้องเพิ่มการตรวจว่า:

- reload ที่มี JSON ผิดรูปแบบไม่ทำลาย ruleset เดิม
- reload ที่มีศูนย์ rule ไม่แทนที่ ruleset ที่ใช้งานได้
- reload ระหว่าง pipeline load ไม่ทำให้ control response ว่าง
- reload สำเร็จต้องมี audit record
- restart แล้ว rules counter ต้องกลับมาเท่ากับไฟล์ canonical

### 4. Detection และ policy coverage

ปัจจุบันมีหลักฐานของ XSS และ synthetic event แล้ว ต้องเพิ่ม coverage สำหรับ SQL Injection, Path Traversal, command injection, file integrity, process telemetry, registry telemetry และ named-pipe telemetry

แต่ละ rule ต้องมี test case อย่างน้อยสามประเภท:

1. positive case ที่ต้องตรวจพบ
2. negative case ที่ต้องไม่ตรวจพบ
3. malformed case ที่ต้องไม่ทำให้ worker หรือ parser ล้ม

### 5. Enforcement safety

ต้องยืนยันว่า Alert, Block, Drop และ Quarantine ให้ผลตรงกับ policy และทุก privileged action ผ่าน Rust PEP ตาม authority invariant เดียวกัน ห้ามใช้ synthetic success เป็นหลักฐานเดียวของ WFP enforcement ต้องมี audit trace, decision, result และ postcondition ที่ตรวจสอบได้

### 6. Performance และ reliability

ยังไม่มีผลรับรองด้าน throughput, latency, queue saturation, memory growth และ long-running stability ต้องทำ benchmark ใน Lab โดยกำหนด baseline และ threshold ล่วงหน้า

อย่างน้อยต้องวัด:

- event throughput
- detection latency
- control command latency
- queue drops
- duplicate/non-monotonic event IDs
- memory growth ระหว่าง long run
- CPU usage ของ ETW, FIM, Registry และ pipeline
- forensic write latency

### 7. Security hardening

ต้องตรวจ ACL ของ named pipes, service account, driver signing, DLL search order, configuration permissions, log permissions และ secret handling ก่อน Production ห้ามใช้การลดสิทธิ์หรือปิด authorization เป็นวิธีแก้ปัญหา runtime

## Roadmap ใหม่ก่อน Production

### Phase P0: Freeze และ evidence baseline

ล็อก commit หรือ build identifier ของ source ที่ผ่าน readiness แล้ว เก็บ health, metrics, rules hash, binary hash, driver hash และ loaded module list เป็น baseline เดียวกัน ห้ามใช้ log เก่าปนกับ log ของ process ใหม่

**Gate:** ทุก artifact มี version/hash และระบุ runtime PID เดียวกัน

### Phase P1: Pre-production installation

สร้างแพ็กเกจสำหรับเครื่องใหม่และทดสอบติดตั้งบน Windows test host ที่ไม่มี build tree เดิมอยู่ ทดสอบ start, stop, uninstall และ rollback

**Gate:** ติดตั้งใหม่ได้โดยไม่ใช้ developer PATH และ health ต้องเป็น `RUNNING` พร้อม worker ทุกตัว

### Phase P2: Control Center validation

ทดสอบ command surface ได้แก่ health, metrics, rules validate, rules reload, events stats และ forensics verify รวมถึง malformed request และ unauthorized request

**Gate:** ทุก response เป็น valid JSON, ไม่มี empty response, ไม่มี pipe leak และ rules reload ผ่านซ้ำอย่างน้อย 20 รอบ

### Phase P3: Recovery validation

หยุดและเริ่ม service ใหม่ ทดสอบ stale ETW session, WFP restart, FIM watcher restart และ named-pipe reconnect ตรวจว่าระบบกลับมา `RUNNING` โดยไม่มี duplicate หรือ orphan resource

**Gate:** recovery สำเร็จตามเวลาที่กำหนดและ `failure_mask` กลับเป็นศูนย์

### Phase P4: Controlled Attack Test ใน Lab

เริ่มจาก synthetic fixtures แล้วเพิ่ม traffic และ activity ที่ควบคุมได้ใน Lab เท่านั้น ทดสอบ detection, policy, PEP, forensic และ recovery หลังแต่ละ scenario

**Gate:** ทุก scenario มี expected result, evidence และ cleanup record ห้ามทดสอบกับระบบหรือเครือข่ายที่ไม่มี authorization

### Phase P5: Production pilot

เริ่มจากเครื่องจำนวนน้อยหรือ monitor-only mode ใช้ canary deployment และมี rollback ที่ทดสอบแล้ว เปิด Block policy เฉพาะ rule ที่ผ่าน false-positive review

**Gate:** pilot ไม่มี critical failure, queue drop, integrity failure หรือ unexplained detection gap

### Phase P6: Production rollout

ขยาย deployment ตามลำดับ พร้อม health monitoring, alerting, backup configuration, signed artifact verification และ incident response procedure

## คำสั่งตรวจ Phase ปัจจุบัน

ใช้คำสั่งผ่าน Control Center เท่านั้น:

```powershell
cd D:\NIDs_Windows

python tools\aegisctl.py health
python tools\aegisctl.py metrics
python tools\aegisctl.py rules validate
python tools\aegisctl.py rules reload
python tools\aegisctl.py forensics verify
```

ผลที่ต้องรักษาไว้ก่อนเริ่ม Controlled Attack Test:

```text
State: RUNNING
Degraded: False
etw_ready: READY
fim_ready: READY
registry_ready: READY
failure_mask: 0
rules_loaded: 22
errors: 0
forensics integrity: ok
```

## คำแนะนำเรื่อง Production

ยังไม่ควรขึ้น Production แบบเต็มรูปแบบในทันที ควรทำ **Pre-production deployment และ Controlled Attack Test** ก่อน จากนั้นจึงขึ้น **Production pilot แบบจำกัดขอบเขต** เมื่อผ่าน installation, recovery, security, performance และ rollback gates

การตัดสินใจที่เหมาะสมคือ:

```text
ตอนนี้: พร้อม Controlled Attack Test ใน Lab
ยังไม่ใช่: Full Production
ขั้นถัดไป: Pre-production package + recovery test + controlled attack matrix
เป้าหมาย: Production pilot แบบ canary หลังทุก gate ผ่าน
```

## Definition of Done สำหรับ Production

ระบบจะถือว่า Production-ready เมื่อสามารถติดตั้งบนเครื่องใหม่ได้โดยอัตโนมัติ ใช้ artifact ที่ตรวจ hash และ signature ได้ มี driver และ DLL contract ที่ตรงกัน มี Control Center ที่ตอบสนองได้เสถียร มี rules reload ที่ปลอดภัย มี recovery procedure ที่ทดสอบแล้ว และมีหลักฐานว่า detection, enforcement, forensic integrity และ performance อยู่ใน threshold ที่กำหนด

## References

[1]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/pasted_content_36.txt "AEGIS NIDS runtime and golden-path validation evidence"
