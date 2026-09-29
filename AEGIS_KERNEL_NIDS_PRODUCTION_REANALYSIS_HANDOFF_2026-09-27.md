# AEGIS — Kernel NIDS/IPS Production Reanalysis Handoff

**Date:** 2026-09-27  
**Project:** AEGIS Windows-native Network Intrusion Detection and Prevention System  
**Target:** Windows Host as NIDS/IPS, Kali VM as attacker, Windows 11 VM as victim  
**Current source HEAD:** `7623d1cf08f9e7dc0768d1043f458cb7fa100c35`

---

## 1. เป้าหมายที่แท้จริงของระบบ

เป้าหมายของ AEGIS ไม่ใช่เพียงการรับ packet แล้วแสดง alert แต่คือการสร้างระบบที่ทำงานเป็นลำดับดังนี้:

```text
รับ traffic จากเครือข่ายทดลอง
        ↓
แปลงเป็น CanonicalEvent ที่ตรวจสอบได้
        ↓
ตรวจจับด้วย Tier-1/Tier-2/Tier-3
        ↓
สร้าง policy decision ที่มีเหตุผลและตัวตนของ event
        ↓
ส่งคำขอไปยัง Rust PEP ซึ่งเป็น authority เดียว
        ↓
ให้ WFP ทำ host enforcement จริง
        ↓
ตรวจสอบผลกระทบที่เกิดขึ้นจริงบน Host
        ↓
สร้าง EnforcementReceipt ที่เชื่อมโยงครบ
        ↓
บันทึก forensic chain
        ↓
Mouth แสดงเฉพาะสถานะที่พิสูจน์แล้ว
```

คำว่า **Kernel NIDS/IPS** ในโครงการนี้หมายถึง:

- การตรวจจับและ telemetry อยู่ใน pipeline หลายชั้น
- การป้องกันที่มีผลต่อระบบ Host ต้องผ่าน WFP และ Rust PEP
- WFP เป็นจุด enforcement ระดับ Windows networking stack
- UI และ detection ไม่มีสิทธิ์อ้างว่าบล็อกสำเร็จเอง
- ผลลัพธ์ทุกอย่างต้องย้อนกลับไปหา event, policy, request และ filter ได้

---

## 2. ข้อสรุปจากการวิเคราะห์ใหม่

โครงสร้างที่พัฒนามาถูกทิศทางแล้ว และไม่ควรเปลี่ยนไปสร้างระบบใหม่แบบแยกส่วนอีก ระบบควรเดินหน้าต่อด้วยแนวทาง **vertical slice เดียวที่พิสูจน์ครบทุกชั้น**

เส้นทางหลักที่ควรรักษาไว้คือ:

```text
Go Nose
  → CanonicalEvent
  → Zig Core
  → Detection/Correlation
  → PolicyDecision
  → Rust PEP
  → WFP provider/callout
  → host effect
  → EnforcementReceipt
  → Forensic
  → Rust Mouth
```

จากผลล่าสุด:

```text
Windows native toolchain      พร้อม
Go Nose                      ผ่านจากผลทดสอบ
Runtime PID/health            ตรงกันใน snapshot ล่าสุด
Zig/Go/C++/Rust workers       รายงาน RUNNING
Tier-3 artifact               พบ aegis_pep.dll
Rust PEP                      canonical enforcement authority
WFP provider                  READY ตาม runtime health
Data-plane counters           ไม่มี drop/error/duplicate ใน snapshot
```

สิ่งที่ต้องทำต่อไม่ใช่การเพิ่ม authority ใหม่ แต่คือการทำให้เส้นทางนี้ **เป็นเส้นทางเดียวที่ใช้งานได้จริงและพิสูจน์ได้ครบ**

---

## 3. สถาปัตยกรรมที่ควรยึดเป็น production architecture

### 3.1 Plane แยกตามอำนาจ

#### Data Plane

รับและส่ง event เท่านั้น:

```text
Npcap/native adapter
Go Nose
CanonicalEvent
Zig event queue
Forensic ring
```

Data Plane ห้ามตัดสินใจ block

#### Decision Plane

วิเคราะห์และสร้างคำขอ:

```text
Zig detection
Python/Cython analytics
correlation
policy compiler
PolicyDecision
```

Decision Plane สร้างคำขอได้ แต่ไม่มีสิทธิ์ทำ WFP mutation

#### Enforcement Plane

มีอำนาจเดียว:

```text
Rust PEP
Rust trust/authorization
WFP provider or callout
filter identity
host-effect verification
EnforcementReceipt
```

Enforcement Plane เท่านั้นที่มีสิทธิ์สร้างผลลัพธ์ `ENFORCED`

#### Presentation Plane

แสดงสถานะจากหลักฐาน:

```text
Rust Mouth
CLI
Dashboard
```

Presentation Plane ต้องไม่แปลง `PolicyDecision(action=block)` เป็น `BLOCKED` เอง

---

## 4. ลำดับการตรวจจับที่ควรใช้

ระบบควรตรวจตามลำดับดังนี้:

```text
Tier-1: packet/flow facts
Tier-2: behavioral and statistical analysis
Tier-3: privileged authorization and enforcement
```

ความหมายของ Tier-3 ต้องไม่ใช่ “ตรวจ packet เพิ่มแบบทั่วไป” แต่เป็นชั้นที่รับเหตุการณ์ที่ผ่านการคัดกรองและมีเหตุผลเพียงพอแล้ว เพื่ออนุมัติหรือปฏิเสธการกระทำที่มีผลต่อ Host

ตัวอย่าง flow:

```text
Kali สร้าง traffic
  ↓
Nose เก็บ packet/flow metadata
  ↓
Zig สร้าง CanonicalEvent
  ↓
Detection พบ pattern หรือ sequence
  ↓
Policy สร้าง block request
  ↓
Rust PEP ตรวจ signature, identity, quota, replay, authority
  ↓
WFP ติดตั้ง filter เฉพาะ flow
  ↓
Rust PEP ตรวจ filter state และ host effect
  ↓
สร้าง receipt
```

หากขั้นใดไม่ผ่าน ให้ผลเป็น:

```text
ALERT_ONLY
ENFORCEMENT_UNAVAILABLE
ESCALATED
REJECTED
```

ห้ามแสดง `BLOCKED_CONFIRMED`

---

## 5. บทบาทของ WFP ในระบบ

WFP ควรเป็นกลไก enforcement หลักบน Windows Host เพราะสามารถผูก policy กับการกรองใน networking stack และสามารถคืนผลการติดตั้ง filter ให้ระบบตรวจสอบต่อได้

การเลือก layer ให้แบ่งตามวัตถุประสงค์:

| วัตถุประสงค์ | Layer ที่พิจารณา | ผลลัพธ์ |
|---|---|---|
| ตรวจ packet IPv4 ขาเข้า | Inbound IP packet | เห็น packet หลัง parse IP header |
| ตรวจ packet IPv4 ขาออก | Outbound IP packet | เห็น packet ใน send path |
| ตรวจ traffic ที่ Host route | IP forwarding | เหมาะกับ topology ที่ Host เป็น gateway |
| ตรวจ TCP stream | Stream layer | เหมาะกับข้อมูล stream ที่ layer รองรับ |
| ตรวจ UDP/datagram | Datagram layer | เหมาะกับ datagram metadata/data |
| ตรวจ process/connection authorization | ALE/transport layers | ผูกกับ endpoint/connection metadata |

หลักการสำคัญคือ WFP ไม่ใช่ Ethernet sniffer และไม่ควรอ้างว่า IP packet layer ให้ L2-L7 visibility เต็มรูปแบบโดยอัตโนมัติ

สำหรับเป้าหมายของ AEGIS วิธีที่เหมาะสมคือทำให้ Windows Host เป็น **routing enforcement boundary** แล้วใช้ WFP ตรวจ traffic ที่ถูก route ผ่าน Host อย่างแน่นอน

---

## 6. Network topology ที่ควรสร้าง

### 6.1 โครงสร้างที่แนะนำ

```text
                 Windows Host
      +--------------------------------+
      | AEGIS Runtime                  |
      | Rust PEP + WFP                 |
      |                                 |
Kali  | VMnet-A  →  Host Route  → VMnet-B |  Victim
192.168.126.10                  192.168.127.10
      +--------------------------------+
```

ใช้ Host-only network สองวง:

```text
VMnet-A: 192.168.126.0/24
Host A:  192.168.126.1
Kali:    192.168.126.10

VMnet-B: 192.168.127.0/24
Host B:  192.168.127.1
Victim:  192.168.127.10
```

Kali ต้องใช้ `192.168.126.1` เป็น gateway และ Victim ต้องใช้ `192.168.127.1` เป็น gateway

Windows Host ต้อง route ระหว่างสอง interface

### 6.2 เหตุผลที่ใช้สอง VMnet

ถ้า Kali และ Victim อยู่บน VMnet เดียวกัน VMware อาจสลับ frame ระหว่าง VM โดยไม่ให้ Host ทำหน้าที่ route IP ดังนั้นการมี Host adapter อยู่ในวงเดียวกันไม่รับประกันว่า Host จะเห็นทุก peer-to-peer flow ใน path ที่ WFP ต้องการ

สอง VMnet ทำให้เส้นทางเป็น:

```text
Kali → Host inbound interface → IP forwarding → Host outbound interface → Victim
```

จึงเหมาะกับการพิสูจน์ WFP ที่ forwarding boundary

### 6.3 ไม่ใช้ VLAN เป็นเส้นทางแรก

VLAN trunking อาจทำได้ในบางสภาพแวดล้อม แต่ไม่ควรเป็นฐานของ first acceptance เพราะต้องพิสูจน์เพิ่มว่า VMware virtual switch, guest driver, Windows adapter และ routing support tag แบบเดียวกัน

สำหรับการเริ่มต้น:

```text
สอง host-only VMnet
static IP
explicit route
explicit interface index
```

เป็นทางเลือกที่ตรวจสอบและ rollback ได้ง่ายกว่า

---

## 7. เส้นทางข้อมูลของแต่ละภาษา

### Go Nose

ทำหน้าที่รับ traffic และส่ง event เท่านั้น

ข้อมูลขั้นต่ำที่ควรส่ง:

```text
source/destination address
source/destination port
protocol
interface index
capture timestamp
payload/metadata length
event ID
producer identity
```

Go Nose ห้ามส่งคำสั่ง block โดยตรง

### Zig Core

รับ CanonicalEvent และทำ:

```text
validation
queueing
ordering
detection orchestration
correlation
forensic sequencing
control/lifecycle
```

Zig ต้องไม่เรียก WFP transport โดยตรงเพื่อ bypass Rust PEP

### Python/Cython Brain

Python/Cython ใช้สำหรับ:

```text
regex and behavioral analytics
feature extraction
scoring
advisory classification
```

Python ไม่ควรมีสิทธิ์เรียก privileged Windows mutation

### Rust PEP

Rust PEP เป็น authority เดียวในการ:

```text
ตรวจ request identity
ตรวจ trust/signature
ตรวจ replay/nonce/quota
ตรวจ policy authority
เรียก provider
อ่านผล provider
ตรวจ host effect
ออก EnforcementReceipt
```

### Rust Mouth

Mouth ควรแสดง:

```text
MATCHED
ALERT
BLOCK_REQUESTED
BLOCKED_CONFIRMED
ENFORCEMENT_UNAVAILABLE
```

`BLOCKED_CONFIRMED` ใช้ได้เฉพาะเมื่อ receipt ผ่าน validation และมี host-effect confirmation

---

## 8. สถานะที่ต้องแยกให้ชัด

ห้ามรวมสถานะเหล่านี้เป็นค่าเดียว:

```text
artifact_present

dependency_ready

provider_ready

host_effect_capable

host_effect_observed

receipt_verified

production_attested
```

ลำดับความหมาย:

```text
artifact_present
  = พบไฟล์ DLL/driver

dependency_ready
  = dependency โหลดได้

provider_ready
  = provider พร้อมรับ request

host_effect_capable
  = runtime ประเมินว่าสามารถทำ effect ได้

host_effect_observed
  = ทดสอบ traffic แล้วเห็น effect จริง

receipt_verified
  = receipt เชื่อมทุก identity และตรวจผ่าน

production_attested
  = ผ่าน full acceptance และ rollback/restart proof
```

Production gate ต้องใช้ `receipt_verified` และ `host_effect_observed` ไม่ใช่ใช้ `provider_ready` เพียงอย่างเดียว

---

## 9. Receipt ที่ต้องสร้าง

Receipt ขั้น production ควรมีอย่างน้อย:

```text
receipt_version
request_id
event_id
policy_id
filter_id
trace_id
audit_id
provider
status
decision
host_effect_confirmed
created_at
reason
```

Receipt ที่ยอมรับเป็น enforcement success ต้องมีเงื่อนไข:

```text
status == ENFORCED
decision == BLOCK
host_effect_confirmed == true
filter_id != 0
request_id != 0
event_id != 0
policy_id != 0
trace_id != 0
audit_id != 0
provider == canonical provider
```

กรณี provider unavailable ต้องออกผลแบบ fail-closed:

```text
status = FAILED หรือ UNAVAILABLE
host_effect_confirmed = false
```

ไม่มี fallback ที่แสดงว่า block สำเร็จจากการตัดสินใจเพียงอย่างเดียว

---

## 10. ขั้นตอนพัฒนาจากสถานะปัจจุบัน

### Phase 1 — Runtime ownership

เป้าหมายคือให้มี runtime owner เพียงตัวเดียว

งาน:

1. ตรวจ process เดิมก่อนเริ่มทุก test
2. หยุด process เดิมผ่าน control plane
3. รอ PID เดิมสิ้นสุด
4. รอ named pipe release
5. เริ่ม process ใหม่
6. ตรวจ health PID ตรงกับ PID ใหม่
7. ปฏิเสธ startup หาก pipe มี owner อยู่แล้ว

เกณฑ์ผ่าน:

```text
expected_pid == observed_health_pid
old_pid is terminated
one control-pipe owner
no stale response
```

### Phase 2 — Brain health

กำหนด UDP health contract ให้ชัด:

```json
{"op":"HEALTH"}
```

ต้องมี response ที่ parse ได้และมี:

```text
component
state
version
ready
```

ถ้า Brain เป็น required component ให้ health gate รอ Brain พร้อม หาก Brain เป็น advisory component ให้ health payload แยก `required_ready` กับ `advisory_ready`

### Phase 3 — Native build and integration

รันครบ:

```powershell
zig build
zig build test
cd nose
go test ./...
cd ..
cargo test
cmake --build build
python -m pytest tests\security tests\contracts tests\runtime tests\wfp -q
```

บันทึก:

```text
compiler version
command
exit code
artifact path
artifact hash
```

### Phase 4 — Lab routing

1. สร้าง VMnet-A และ VMnet-B
2. ตั้ง static IP
3. ตั้ง default gateway ให้ Kali และ Victim
4. เปิด routing ที่ Host ตามแผน
5. บันทึก interface index
6. ตรวจ route table
7. ทดสอบ ping และ TCP benign flow
8. ตรวจว่า traffic ผ่าน Host

### Phase 5 — Observe-only

เกณฑ์ผ่าน:

```text
Nose accepts events
CanonicalEvent validates
Zig processes events
forensic records increase
integrity verifies
no enforcement request occurs
```

### Phase 6 — Detection canary

ใช้ traffic ที่ควบคุมได้และ pattern ที่ไม่เป็นอันตรายเกินไป

เกณฑ์ผ่าน:

```text
rule matched
policy decision created
decision trace created
no WFP mutation until explicit enforcement gate
```

### Phase 7 — WFP host-effect canary

ใช้ flow เดียวและ filter แคบที่สุด

เกณฑ์ผ่าน:

```text
Rust PEP authorizes
provider installs filter
filter_id returned
traffic is blocked
unrelated traffic remains available
receipt validates
forensic record validates
```

### Phase 8 — Cleanup

```text
remove exact filter by filter_id
query filter = absent
traffic restored
cleanup receipt/forensic record valid
```

### Phase 9 — Restart and recovery

```text
old runtime exits
new runtime starts
new PID owns pipe
provider reloads
old filter absent
workers ready
forensic generation valid
```

### Phase 10 — Production acceptance

Production acceptance ต้องประกอบด้วย:

```text
native build pass
full test pass
truth artifacts regenerated
observe-only proof pass
detection proof pass
host-effect proof pass
cleanup proof pass
restart proof pass
no duplicate authority
no stale runtime
no unverified BLOCKED state
```

---

## 11. การทดสอบโจมตีใน VMware

หลังจากระบบผ่าน controlled WFP canary แล้วจึงเริ่ม attack scenarios

แบ่งเป็นสามกลุ่ม:

### Network reconnaissance

```text
port discovery
service enumeration
ICMP/ARP behavior
```

### Protocol abuse

```text
invalid protocol sequences
malformed requests
repeated connection attempts
DNS/TLS anomalies
```

### Host-impact scenarios

```text
suspicious connection pattern
credential access simulation
lateral movement simulation
process/network correlation
```

ทุก scenario ต้องมี:

```text
scenario ID
attacker address
victim address
expected event
expected policy
expected action
expected receipt
expected forensic record
cleanup result
```

การทดสอบโจมตีไม่ควรเริ่มจาก broad blocking หรือ production network ต้องเริ่มจาก test tuple ที่รู้ผลล่วงหน้าและทำ rollback ได้

---

## 12. Definition of Done

ระบบถือว่าเข้าสู่ Production Acceptance ได้เมื่อ:

- มี runtime owner เดียว
- control pipe ไม่ตอบข้อมูลจาก process เก่า
- Brain health contract ผ่าน
- Go Nose รับ traffic และไม่ทำ policy decision
- CanonicalEvent มี event ID ต่อเนื่องและตรวจซ้ำได้
- Detection สร้าง finding โดยไม่ block เอง
- Rust PEP เป็น enforcement authority เดียว
- WFP provider ติดตั้ง filter จริง
- filter identity ถูกอ่านกลับได้
- traffic ที่กำหนดถูก block จริง
- traffic อื่นยังทำงานได้
- receipt เชื่อม event/policy/request/filter/trace/audit ครบ
- forensic chain ตรวจผ่าน
- Mouth แสดง confirmed state จาก receipt เท่านั้น
- cleanup ลบ exact filter สำเร็จ
- หลัง restart ไม่มี stale filter
- truth artifacts สร้างจาก current HEAD
- full regression suite ผ่าน

---

## 13. คำสั่งเริ่มต้นสำหรับ AI session ถัดไป

```text
ทำงานต่อที่ D:\NIDs_Windows
อ่าน AGENTS.md และ machine-readable maps ก่อน
ตรวจ current HEAD และ git status
ห้ามสร้าง authority ใหม่
ห้ามแก้ manifest ด้วยมือ
เริ่มจาก lifecycle single-owner และ Brain health
ใช้ Host-only VMnet สองวง
ให้ Windows Host เป็น router ระหว่าง Kali กับ Victim
ใช้ WFP เป็น enforcement authority ผ่าน Rust PEP เท่านั้น
ทำ observe-only proof ก่อน
ทำ WFP canary แบบ filter แคบ
ตรวจ host effect จริง
สร้าง receipt และ forensic evidence
ทำ cleanup และ restart proof
จึงค่อยประกาศ Production Acceptance
```

---

## 14. Final handoff statement

AEGIS ควรเดินหน้าต่อด้วย architecture ปัจจุบัน ไม่ควรย้อนกลับไปใช้ promiscuous-mode assumption เป็นแกนกลาง และไม่ควรเพิ่ม Rust Shield หรือ firewall path ที่สอง

แนวทางที่เหมาะสมที่สุดคือ:

```text
Windows Host
  + AEGIS runtime
  + Rust PEP
  + WFP provider/callout
  + two isolated VMware host-only networks
  + Host routing boundary
  + Kali attacker
  + Windows 11 victim
```

โครงสร้างนี้ทำให้สามารถทดสอบได้เป็นลำดับจาก:

```text
traffic visibility
→ detection
→ policy
→ authorization
→ WFP effect
→ receipt
→ forensic
→ cleanup
→ recovery
```

งานต่อไปที่สำคัญที่สุดคือทำให้ lifecycle test ใช้ process owner ที่ถูกต้อง และทำให้ Brain health endpoint ตอบตาม contract จากนั้นจึงเข้าสู่ WFP host-effect canary บนสอง VMnet

นี่คือเส้นทางที่ตรงที่สุดจากระบบปัจจุบันไปสู่ Kernel-level NIDS/IPS ที่พิสูจน์ผลได้จริง
