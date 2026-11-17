# G2-ENFORCEMENT-RETIRED-20261117 — policy ถึง PEP จริง แต่ PEP ไม่ทำ host effect อีกแล้ว

**วันที่:** 2026-11-17 (window 15:27–15:46 local, 08:27–08:46 UTC)
**Base HEAD:** `23f5961` (records), build source `7c604d5`
**Gap:** `EVI-G2-PEP-CACHE-001-LAB-20261023` (E5, เดิม PARTIAL)
**Patch record:** `PATCH-ID G2-RETIRE-CLOSE-20261117` / `FLOW-ID ENF-001`

---

## 1. ข้อสรุป (อ่านบรรทัดนี้ก่อน)

1. **canary ผ่าน policy จริง** — v2 lab policy (`dst_port eq 443` + `rule_id gt 0`
   → `quarantine`) match event ของ canary และขึ้น audit row `policy=3`
2. **แต่ PEP ไม่ยอมทำ host effect** — `aegis_pep_enforce` ตอบ
   `decision=escalate`, `reason=8`, `filter_id=0` ทุกกรณี BLOCK/QUARANTINE
   (reason 8 = `detection-only: host effect retired by product scope`, issue #25 /
   `RETIRE-HOST-EFFECT-001`)
3. **ดังนั้นขั้นที่เหลือของ gap นี้รันไม่ได้บน source ปัจจุบัน** — ไม่มี filter id
   ให้ query direction, ไม่มี filter ให้ duplicate, ไม่มี filter ให้ unblock
   (ขั้นเหล่านี้ **ไม่ได้รัน** และไม่มีการอ้างว่ารัน)
4. **G2 จึงถูกจัดสถานะใหม่เป็น CLOSED แบบ superseded by scope retirement** ไม่ใช่
   "ผ่านครบ 7 ขั้น" — เหตุผลอยู่ใน §7
5. **host ถูก restore ครบและตรวจซ้ำแล้ว** — hash, env, sig/trust, firewall, filter census,
   posture (§6)

---

## 2. สิ่งที่รันจริงใน window นี้

| ขั้น | ผล |
|---|---|
| preflight (elevated, read-only + backup) | 3 ครั้ง; ครั้งสุดท้าย `WFP_PROVIDER_FILTERS=0`, `WFP_PROVIDER_DEFINED=1`, `PORT_443_LISTENERS=0`, `PORT_8443_LISTENERS=0`, `SERVICE_ENV=AEGIS_LOSS_BUDGET=3500`, `LAB_RULE_COUNT=0`, gate closed |
| lab daemon install (UAC) | `aegis_nids.exe` = `F805F4DC2C7E978E2D5DA34CED7106BFCFC52E2AD2A609465728B3164550BA92` (5,267,456 B) |
| v1 lab policy (2026-10-21) | `db67b1b5465bc1b17ae2ac4b73506daf4b00067f5fd57054aa75d8f8b48035f9` — **match ไม่ได้** (§3) |
| v2 lab policy install (UAC) | sha256 `71d935348346d23e62e74af5421a5d06831e5080c0f6360c568d58c4da86890f`, `POLICY_VALID=True`, `ANCHOR_SOURCE=file`, `GATE=open`, `TIER3_ENFORCING=True`, `HOST_EFFECT_CAPABLE=True` |
| canary c1 (payload) | ACCEPT, listener ได้ `DATA ... bytes=104`; audit `policy=3` **decision=escalate** (§4) |
| PEP ABI probe (direct FFI) | `reason=8`, `filter_id=0` (§5) |
| restore (UAC) | ทุกค่าตรง baseline (§6) |

ค่าที่บันทึกจาก install: `SERVICE_ENV_AFTER=AEGIS_LOSS_BUDGET=3500|AEGIS_POLICY_ENFORCE_TRUSTED=1`,
`ENFORCEMENT_MODE=provider-attested-enforcement-enabled`, log
`signed enforcement: 1 policies marked trusted (envelope VALID)` และ
`LAB: prevention gate OPEN (opened)`.

> lab build คือ `zig build -Dlab-prevention-gate=true`;
> `zig-out\bin\aegis_nids.exe` (default) ยังเป็น `7955A6E3...` และไม่มี marker
> `lab_prevention_gate_open` — ตรวจแล้วทั้งสองไฟล์ในรอบนี้

---

## 3. ทำไม policy v1 (2026-10-21) match ไม่ได้

`src/pipeline/event_processor.zig` ประเมิน policy เฉพาะเมื่อ `matched_rule_id != 0`
และทุกเส้นทางที่ตั้ง `matched_rule_id` (signature / L4 / correlation) เขียน
`ev.kind` ใหม่เป็น `signature_match` / ค่าอื่นที่ไม่ใช่ `packet_captured`
policy เดิมจึงเป็นไปไม่ได้เชิงโครงสร้างที่จะ match บน source ปัจจุบัน

**หลักฐาน:** canary แรกของวันนี้ (bare connect, port 443, label c1) ได้
`CANARY=ACCEPT`, listener ได้ `ACCEPT 192.168.126.10`, `confirmed_quarantines`
คงที่ 0, และ diagnostic log ไม่มีบรรทัด policy/quarantine ใด ๆ

---

## 4. canary c1 (payload) — policy match จริง แต่ PEP escalate

แคมเปญ: `g3_canary_payload.py` (SQLi `' OR 1=1` ใน path) จาก Kali
`192.168.126.10` → host `192.168.126.1:443`

| ค่า | ผล |
|---|---|
| guest result | `CANARY=ACCEPT` (elapsed 2.002 s — listener ถือ connection) |
| listener | `ACCEPT 2026-11-17T15:42:25 192.168.126.10:39740` + `DATA ... bytes=104` |
| audit row | `policy=3 pep_req=1 decision=escalate result=logged_only src=c0a87e0a:39740 dst=c0a87e01:443 proto=6` |
| dispatcher | `action=escalate event=signature_match` |
| metrics | `confirmed_quarantines 0 → 0`, `confirmed_blocks 0`, `detections 11 → 16` |
| perf | `src_ip`/`dst_ip` ใน audit เป็น hex: `c0a87e0a` = 192.168.126.10, `c0a87e01` = 192.168.126.1 |

ข้อความนี้พิสูจน์เฉพาะ "policy engine → PEP request" ไม่ได้พิสูจน์ host effect

---

## 5. PEP ABI probe — สาเหตุคือ reason=8

เรียก `aegis_pep_enforce` ตรงจาก Python (layout ตรงกับ `src/policy/pep_bindings.zig`:
`sizeof(req)=64`, `sizeof(resp)=24`, `ctx offset=40`):

```json
{"label":"quarantine_capable","capability_mask":1,"rc":0,"decision":"escalate","reason":8,"filter_id":0,"quota_remaining":99}
{"label":"quarantine_no_capability","capability_mask":0,"rc":0,"decision":"escalate","reason":1,"filter_id":0}
{"label":"block_capable","capability_mask":1,"rc":0,"decision":"escalate","reason":8,"filter_id":0}
{"label":"alert_unsigned","capability_mask":0,"rc":0,"decision":"allow","reason":0,"filter_id":0}
```

`reason=8` ตรงกับ source ที่ติดตั้ง:

- `rust-src/lib.rs` (ราวบรรทัด 915–928): เมื่อ decision เป็น BLOCK/QUARANTINE
  จะถูกแปลงเป็น `DECISION_ESCALATE`, `reason = 8`, `filter_id = 0` และ
  **ห้าม load/probe/invoke adapter** (product decision, issue #25)
- `AUTHORITY_MAP.json` note: *"The Rust PEP is a detection-only policy evaluator … no
  host-effect authority in production (RETIRE-HOST-EFFECT-001, issue #25)"*
- `GAP-TRIAGE-20261116.md` ระบุว่า G2 เป็น enforcement-lab gap ที่
  "none — enforcement is out of product scope"

capacity gate ยังทำงาน (reason=1 เมื่อไม่มี capability bit 0x01) และ alert ยัง
`allow` — แปลว่าไม่ได้พังทั้งกระบวน แต่ BLOCK/QUARANTINE ถูก retire ตาม scope

---

## 6. Restore (ปิด window) — hash-verified

`g3_restore.ps1` (elevated) รายงาน:

```text
HASH_MATCH=True
DRIVER_MATCH=True
POLICIES_MATCH=True
SIG_PRESENT=False
TRUST_PRESENT=False
SERVICE_ENV_RESTORED=AEGIS_LOSS_BUDGET=3500
FIREWALL_RULE_LEFT=0
WFP_PROVIDER_FILTERS=0
SERVICES_AFTER=AegisNids=Running,AegisWfp=Running
GATE=closed
TIER3_ENFORCING=False
HOST_EFFECT_CAPABLE=False
ENFORCEMENT_MODE=detection-only
```

ตรวจซ้ำแบบไม่พึ่งสคริปต์:

| ไฟล์ | hash ที่อ่านได้ |
|---|---|
| `aegis_nids.exe` | `7955A6E3C9BB8AC4E5872114B33316AADA74F09E39F48C0513BA6FFA58D71A18` |
| `aegis_pep.dll` | `362B069AFF007B6C72494D2B9E689893C1A8EB559B8266B38534AA17D543D118` |
| `aegis_wfp.sys` | `06CC8E238B79BEC3782F4036BACF058D6B5291B030E59D061FD692F82FB96B50` |
| `configs\policies.json` | `B7224FA01572A637336AF6629D2A63C44FD9C53854DFD401D6264E5249CA3A4E` |

`policies.sig.json` / `policy_trust.json` = absent, service env มีค่าเดียว
`AEGIS_LOSS_BUDGET=3500`, firewall rule `AEGIS-G2-LAB-443` = 0,
`prevention_gate=closed`, `tier3_enforcing=false`, `host_effect_capable=false`,
`enforcement_mode=detection-only`, `policy_verify.policies.valid=false`
(reason `SIDECAR_ABSENT`) ซึ่งถูกต้องสำหรับ baseline ที่ไม่ลงนาม

---

## 7. ผลต่อ gap และเหตุผลที่จัดเป็น CLOSED (superseded)

gap นี้อ้าง `expected` ว่า duplicate canary ต้องได้ "second confirmed
quarantine/receipt หรือ documented block" ซึ่งต้องมี **filter ของ AEGIS** เป็น
เงื่อนไขตั้งต้น แต่บน source ปัจจุบันไม่มีเส้นทางใดสร้าง filter ได้เลย:

- PEP คืน `filter_id=0` (reason 8) ทุกครั้ง — พิสูจน์ด้วย direct FFI
- ไม่มี AEGIS provider filter ใน WFP ทั้งก่อนเปิด window, ระหว่าง, และหลัง restore
  (`WFP_PROVIDER_FILTERS=0` ทั้งสามจุด)
- จึงไม่มี `direction verify`, ไม่มี duplicate filter, ไม่มี receipt-aware unblock
  ให้ทดสอบ — **ขั้น C2–C7 ของแผน rev.2 รันไม่ได้โดยชอบ**

การคง gap นี้เป็น OPEN จะเป็นการบอกว่ายังมีงาน enforcement ค้างอยู่ ซึ่งขัดกับ
`AUTHORITY_MAP.json` และ `RETIRE-HOST-EFFECT-001` ที่ปิด issue #25 ไปแล้ว
(= เอกสาร contradiction; แก้ที่เอกสาร ไม่ใช่แก้ที่ source)

**ผลลัพธ์ที่บันทึก:** `CLOSED` — superseded by product-scope retirement, E5,
พร้อมหลักฐานว่าห่วงโซ่ policy→PEP ยัง match จริงและ PEP ปฏิเสธ host effect ตามดีไซน์

**สิ่งที่ไม่เคยเกิดขึ้น (และห้ามอ้าง):** filter id, direction verify, duplicate
block, unblock/reachability canary, `confirmed_quarantines > 0`

---

## 8. หลักฐาน (local-only, `admin-evidence/` git-ignored)

`admin-evidence/g2-single-host-20261117/`

| ไฟล์ | sha256 | bytes |
|---|---|---|
| `window-20261117/listener.log` | `7C8154B6F4ED68DCA874C21EC8FEAAEA5BAAE01BFA6D6005A5946B4D3CF90BB7` | 185 |
| `window-20261117/c1b.json` | `BC3CBC529A934E748105347D20BE0960B33B378F43DDE200F8CE2AAC1EB872D5` | 262 |
| `window-20261117/before-c1b.json` | `F2567217BEA36BA31201A0FFB2CE5D721C03477A9EFBDC82E6B77016DD7B31FF` | 6047 |
| `window-20261117/after-c1b.json` | `A9BF63DA6FE9D95B52599374BA8A838F27063B3AC1950FAB2722FC867B2C591E` | 6048 |
| `window-20261117/diag-c1b.txt` | `BF11913E32635FCC369A05B23C9FC1A4A91A8F0D7A9D70E0A0AEF736159F8E4E` | 22197 |
| `window-20261117/pep-abi-probe.txt` | `B0609D9FDF1168792D68BB38D3CC9C1E090214027492CCA3A45CDAAB138CAAF4` | 1854 |
| `window-20261117/post-restore.json` | `1B577CB507F2FDA8E832C686C704781D8C071F3963F722B801B44131BF0AA61D` | 1111 |
| `preflight-20261117T083535Z/preflight.json` | (backup + hashes ครบใน `backup-SHA256SUMS.txt`) | — |
| `preflight-20261117T083535Z/install-20261117T083646Z/install.json` | `HOST_EFFECT_CAPABLE=True`, gate open | — |
| `preflight-20261117T083535Z/policy-v2-20261117T084126Z/install-policy.json` | `POLICY_VALID=True` | — |
| `preflight-20261117T083535Z/restore-20261117T084650Z/restore.json` | `33FD6C890310D1F61489532A516C12BD9E0EE307DFA3B9C4AD313C98FB1E5F24` | 2741 |
| `elevated-g3_install_lab-20261117T083645Z.log` | `GATE=open` | — |
| `elevated-g3_install_policy-20261117T084126Z.log` | `POLICY_SHA256=71D93534...` | — |
| `elevated-g3_restore-20261117T084650Z.log` | `HASH_MATCH=True` | — |

kit ที่ใช้: `lab-kit-v3/` (16 ไฟล์ + `SHA256SUMS.txt`), key/trust ของ v2 อยู่ที่
`lab-policy-v2/` (`lab-key-v2.pem` เป็น lab-only, ไม่อยู่ใน repo)

---

## 9. Patch record

```text
PATCH-ID:        G2-RETIRE-CLOSE-20261117
FLOW-ID:         ENF-001
TARGET HEAD:     23f5961
TARGET FILES:    EVIDENCE_INDEX.json
                 analysis/current-head/G2-ENFORCEMENT-RETIRED-20261117.md (new)
                 analysis/current-head/CLOSURE-PLAN-5GAPS-20261117.md (rev.3 amendment)
IN-SCOPE:        gap reclassification + evidence record + plan correction
OUT-OF-SCOPE:    any src/, driver, PEP, Rust, build, release, tag change
CONTRACT IMPACT: none
ABI IMPACT:      none (PepRequest 64 B / PepResponse 24 B observed only)
AUTHORITY IMPACT: none — confirms existing detection-only authority
STATE IMPACT:    host restored to baseline; no filter, no sig/trust, env restored
TEST IMPACT:     none
EVIDENCE IMPACT: +1 E5 evidence entry; gap status OPEN -> CLOSED
```

**ROLLBACK:** revert this records commit; the host needs no rollback (already baseline).
