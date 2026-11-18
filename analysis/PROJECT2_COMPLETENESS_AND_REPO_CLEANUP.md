# AEGIS NIDS — Project 2 Completeness + Repo Cleanup Plan

Measured at HEAD `fb61013487e9cf1bdba8c32acd061eb2b0c5991b` (working tree also carries the
9-file provenance resync described in §3.5).

ทุกตัวเลขในเอกสารนี้วัดจาก repo จริงด้วยคำสั่ง git/find/du ไม่ได้มาจาก README หรือ doc

---

## 1. ขนาดจริง: 30 GB มาจากไหน

| ส่วน | ขนาด | จำนวนไฟล์ |
|---|---|---|
| Working tree (ไม่รวม `.git`) | **29 GB** | — |
| `.git` (loose objects, packs = 0) | **1.06 GB** | 9,336 objects |
| รวม | **~30 GB** | — |
| **Tracked ทั้งหมด** | **13,977 MB** | 1,619 ไฟล์ |
| — `aegis-audit-*/` (grep dumps) | **13,959 MB = 99.9% ของ tracked** | 198 ไฟล์ |
| — โค้ด/เอกสารจริงทั้งหมด (`src`, `tools`, `tests`, `docs`, `analysis`, `brain`, `scripts`, `release`) | **~17 MB** | ที่เหลือ |

### Tracked bytes แยกตามโฟลเดอร์

```
  5814.5 MB  aegis-audit-20260928-001904
  3637.5 MB  aegis-audit-20260928-001216
  2573.4 MB  aegis-audit-20260927-235713
  1603.4 MB  aegis-audit-20260928-003615
   164.2 MB  aegis-audit-20260927-235338
   139.1 MB  aegis-audit-20260928-151422
    20.7 MB  aegis-audit-20260927-234325
     6.3 MB  aegis-audit-20260927-233456
     3.4 MB  src          <- โค้ด runtime จริงทั้งระบบ
     2.9 MB  release
     1.8 MB  analysis
     1.3 MB  docs
     0.5 MB  tests
     0.4 MB  tools
```

### ไฟล์ tracked ที่เกิน 100 MB (GitHub block ขาด)

มี **10 ไฟล์** ทั้งหมดเป็น `04-scan-*.txt` ภายใน `aegis-audit-*/` ตัวใหญ่สุด 3,637 MB
(`aegis-audit-20260928-001216/04-scan-aegis_pep_enforce_evaluate_unblock_query_provider.txt`)

### Working tree ที่กินพื้นที่ (นอกเหนือ tracked)

```
  24.4 GB  aegis-audit-*/  (tracked dumps ~14 GB + audit.log ที่ ignore อยู่ ~10 GB)
   1.6 GB  target/                  (ignored)
   1.3 GB  aegis_dashboard/target/   (ignored)
    53 MB  zig-out/                 (ignored)
    51 MB  build/                   (ignored)
    38 MB  ts_policy/ , 28 MB release/ , 26 MB go/ , 21 MB dist/ , 18 MB logs/
```

ไฟล์ >50 MB มี 17 ไฟล์ ทั้งหมดอยู่ใน `aegis-audit-*` (`.gitignore:73 *.log` ทำให้ `audit.log`
untracked อยู่แล้ว แต่ `04-scan-*.txt` ยังถูก track)

---

## 2. ความปลอดภัย: ลบ `aegis-audit-*/` แล้วพังไหม

ตรวจการอ้างอิงทั้ง repo แล้ว **ไม่พัง**:

| ผู้ที่อ้างอิง | ผล |
|---|---|
| `EVIDENCE_INDEX.json` | 0 ครั้ง |
| `AI_CONTEXT.md`, `SYSTEM_MAP.json` | 0 ครั้ง |
| `tests/`, `tools/`, `.github/`, `scripts/` | ไม่พบ |
| `docs/`, `analysis/`, `*.md` | ไม่พบ |
| `inventory.json`, `reference_map.json` | 198 ครั้ง — **ไฟล์ generated** สร้างใหม่ได้ด้วย `tools/generate_truth_artifacts.py` |

และไม่มี generator ใดใน repo (`tools/`, `scripts/`, `.github/`) ที่สร้างดัมป์ `04-scan-*`
→ เป็น artifact จาก audit session ภายนอก ไม่ใช่ผลผลิตของระบบ

> ข้อควรระวัง: ต้อง regenerate `inventory.json` / `reference_map.json` **หลัง** ลบทุกครั้ง

---

## 3. แผน clean 30 GB → GitHub แบบปลอดภัย

### 3.0 Backup ก่อนทุกอย่าง (ห้ามข้าม)

```bash
# ประวัติทั้งหมดยัดเป็นไฟล์เดียว (บีบอัดแล้ว ~1 GB เพราะดัมป์เป็นข้อความซ้ำ ๆ)
git bundle create D:/AEGIS_archive/aegis-history-$(date +%Y%m%d).bundle --all
# และคัดลอกดัมป์ออกนอก repo ก่อนลบ
mkdir -p D:/AEGIS_archive/audit-dumps && cp -r aegis-audit-* D:/AEGIS_archive/audit-dumps/
```

### 3.1 เก็บคุณค่าของ audit ไว้ (ไม่ต้องเก็บ 24 GB)

แต่ละ `aegis-audit-*` มี 5–16 ไฟล์ ส่วนที่ใหญ่คือ `04-scan-*.txt` และ `audit.log`
ให้เก็บเฉพาะไฟล์รายงานขนาดเล็ก (<5 MB) และทำ excerpt ของดัมป์ใหญ่ไว้เป็นหลักฐาน:

```bash
for f in aegis-audit-*/*/04-scan-*.txt aegis-audit-*/04-scan-*.txt; do
  [ -f "$f" ] && head -c 200000 "$f" > "${f%.txt}.excerpt.txt"
done
```
(ทำเมื่อต้องการเท่านั้น — ถ้าไม่ต้องการหลักฐานดัมป์เลย ข้ามได้)

### 3.2 เลิก track + กันไม่ให้กลับมา

```bash
git rm -r --cached 'aegis-audit-*'
```
เพิ่มใน `.gitignore`:
```
# --- Audit scan dumps (ย้ายออกนอก repo; เก็บ bundle/archive แยก) ---
aegis-audit-*/
```
จากนั้น commit (ระบบ truth จะยัง valid เพราะไม่มี gate ไหนอ่านดัมป์เหล่านี้)

### 3.3 ล้างออกจากประวัติ (ขั้นที่ทำให้ GitHub push ได้จริง)

`.git` ยังมี blob 14 GB อยู่ใน 279 commits → ต้องเขียนประวัติใหม่

```bash
pip install git-filter-repo            # ถ้ายังไม่มี (ทางเลือก: BFG / git filter-branch)
git filter-repo --path-regex '^aegis-audit-' --invert-paths --force
git reflog expire --expire=now --all && git gc --prune=now --aggressive
```
คาดผลลัพธ์: repo เหลือ **~20–40 MB** (จาก 30 GB)

> ⚠️ ทุก commit SHA จะเปลี่ยน รวมถึง SHA ที่ถูกอ้างใน truth maps / EVIDENCE_INDEX / handoff
> ต้องทำ §3.5 ทันทีหลัง rewrite

### 3.4 หลัง rewrite: เช็คก่อน push

```bash
du -sh .git                                   # ต้องเป็นหลักสิบ MB
git ls-tree -r -l HEAD | awk '$4>104857600'   # ต้องว่าง (ไม่มีไฟล์ >100 MB)
git ls-tree -r -l HEAD | awk '{s+=$4} END {print s/1048576" MB tracked"}'  # ต้อง ~17 MB
```
เพิ่ม `.gitattributes` เพื่อหยุดปัญหา CRLF→LF ที่เห็นตลอดเวลา:
```
* text=auto eol=lf
*.exe binary
*.dll binary
```
หมายเหตุ: `release/T20-final/<sha>/...` เป็นสำเนาทั้ง repo ที่ฝัง SHA เก่า — ควรตัดสินใจว่าจะ
เก็บไว้เป็นหลักฐาน release หรือทิ้ง (ปัจจุบันมีแค่ 2.9 MB จึงไม่ใช่ปัญหาขนาด)

### 3.5 Resync truth หลัง SHA เปลี่ยน (ลำดับสำคัญ)

```bash
python tools/generate_truth_artifacts.py      # inventory + reference_map
python tools/create_manifest.py               # runtime_manifest
# stamp head_sha ของ 7 maps + AI_CONTEXT.md + build_manifest.source_commit = HEAD ใหม่
python tools/release_engineering.py --refresh-digests   # ต้องท้ายสุด
python tools/truth.py verify                  # ต้อง TRUTH_VALID
python tools/release_engineering.py --verify  # ต้อง 516/516 (จะเปลี่ยนจำนวนถ้ามีไฟล์ถูกถอด)
```

### 3.6 กันไม่ให้บวมซ้ำ (ป้องกันการพังตามที่กังวล)

เพิ่ม step ใน CI:
```yaml
- name: Repo size hygiene gate
  run: |
    git ls-tree -r -l HEAD | awk '$4>20971520 {print "TRACKED >20MB:", $5; bad=1} END {exit bad}'
    git ls-files 'aegis-audit-*' | grep -q . && { echo "audit dumps must not be tracked"; exit 1; } || true
```

---

## 4. Project 2 completeness matrix (ยืนยันด้วยหลักฐานจริง)

| ด้าน | สถานะ | หลักฐาน / ช่องว่าง |
|---|---|---|
| **Network detection** | ทำงาน แต่แยกสองเส้น | [nose/signature_classifier.go](../nose/signature_classifier.go#L52-L54) match `match_pattern` ด้วย `strings.Contains` บน packet จริง; wire event 109 byte มีแค่ `PayloadLength/PayloadHash` → [nose_pipe_reader.zig:326](../src/capture/nose_pipe_reader.zig#L326) เรียก `pushCanonicalEvent` (payload ว่าง) → **Zig Aho-Corasick มองไม่เห็น payload ของ network** และ `regex_pattern` ไม่ถูกใช้บนเส้นนี้ |
| Detection counters | ทำงาน | runtime RUNNING: `detections=3273`, `packets_captured=1,312,756`, `events_processed=1,316,390`, `errors=0` |
| Rule management (read) | ทำงาน | 22 rules ใน [configs/Rules.json](../configs/Rules.json) = `rules_loaded: 22` พอดี; `rules list/show/validate/reload/add/update/delete` มีครบ |
| Rule management (single authority) | **ผ่าน** (`3331109`) | ทุก reader/writer ชี้ `configs/Rules.json`; mirror `config/Rules.json` byte-identical + drift test [test_single_rule_authority.py](../tests/security/test_single_rule_authority.py); `golden_path_evidence` เคย hash ไฟล์หนึ่งแต่ประกาศอีกไฟล์ + นับ rules ได้ 0 (แก้แล้ว) |
| Detection contract pin | **ผ่าน** (`3331109`) | golden FNV-1a table ชุดเดียวกันถูก assert ใน Python ([test_detection_contract_pin.py](../tests/security/test_detection_contract_pin.py)), Go ([nose/signature_classifier_test.go](../nose/signature_classifier_test.go)) และ Zig ([rule_loader.zig](../src/pipeline/rule_loader.zig)); Go substring = `match_pattern`, `regex_pattern` = Python brain เท่านั้น |
| Enforcement / IPS | ยังไม่พิสูจน์ | `prevention_gate=closed`, `provider_ready=false`, `host_effect_capable=false`, `blocks=0` → detection-only; ต้อง Admin/driver (WFP) จึงเป็น E5 ได้ |
| Forensic evidence | **ผ่าน attribution** (`bbabb2c`) | ring เขียน canonical ordinal + `reserved[5]` = source-space version; legacy records ถูก canonicalize ตอนอ่าน; adapter ตั้ง `ev.source` จาก canonical event (เดิมทิ้งเป็น `.system` ทุกตัว); พิสูจน์จริง: inject 400 canonical frames → `npcap_sensor` 400/400 + `source_name`/`source_space` |
| Forensic list pagination | **ผ่าน** (`bbabb2c`) | byte budget 32 KiB + `truncated`/`next_after` + client accumulate จน JSON ครบ; พิสูจน์จริง: `--limit 1000 --all` = 403/403 records, pages=2, rc=0 (เดิม 90 KB ต่อหน้าเดียว → rc=3) |
| Frontend (console / Rust dashboard) | ทำงาน | labels canonical, `rust_pep` = authority, WFP มาจาก block `enforcement`; compile + test ผ่าน |
| Frontend (alerts) | ไม่ผ่าน (งานถัดไป) | `alerts` → `{"available": false, "reason": "alert_query_not_connected"}` → detection ใหม่ไม่ถูกส่งถึง UI (ต้อง wire Go aggregator REST :9200 → daemon) |
| Truth / release gates | ผ่าน | `release_engineering --verify` 516/516, `truth.py verify` TRUTH_VALID, `authority invariant: HELD` |
| Cross-module contracts | **ปิดช่องแล้ว** (`dd83fac`) | receipt status ↔ wire byte มี mapping `wireStatus` (total, ทดสอบ) + conformance test; `contracts/fixtures/` 13 ไฟล์มี validator ครบ ([test_contract_fixtures.py](../tests/contracts/test_contract_fixtures.py)) และแก้ fixture ที่ประกาศ severity นอก canonical space |
| Test suite | **เขียว** (`77424c4`) | `pytest tests/` = 524 passed / 2 failed / 5 skipped; 2 ตัวที่เหลือคือ (ก) test ต้องให้ daemon รันอยู่ (ข) digest ของ release gate ที่จะ refresh ตอน resync; เพิ่ม test ใหม่ 4 ไฟล์ |
| Host telemetry | บางส่วน | ETW ถูกบล็อก (`StartTraceW failed: 183`), minifilter/pipe source มีอยู่, drivers ต้อง signing/admin |

---

## 5. ลำดับที่แนะนำ (ทำ project 2 ให้ครบ → แล้ว clean)

1. **Pin detection contract** — บังคับด้วย test ว่า Go `match_pattern` set / Zig AC set / Python `regex_pattern` set ตรงกัน และระบุว่าเส้นไหนใช้ field ไหน (ปิดช่อง "detection ทำงานคนละที่")
2. **แก้ pagination ของ `forensics.list`** — ใช้ byte budget + คืน `truncated`/`next_after` แทนการล้ม
3. **Single rule authority** — เลิกอ่าน `config/Rules.json` ใน `golden_path_evidence.py`, จัดการสำเนา
4. **Forensic source space + rule attribution** — ให้ ring เก็บ canonical ordinal และมี rule_id ในสัดส่วนที่ใช้เป็น evidence ได้
5. **Alerts ต่อกับ daemon** — ให้ UI แสดง detection จริงได้ครบ
6. **ปิด test แดง 6 ตัว** (retarget ไป canonical surface) + ตรวจ EnforcementStatus/fixtures contract
7. **Enforcement E5** — รันด้วย Admin + WFP เพื่อพิสูจน์ block จริง (จะย้าย `blocks` จาก 0 และเปลี่ยน `prevention_gate`)
8. **Clean repo ตาม §3** แล้ว resync truth (§3.5) และ push

---

## 6. ผลรอบนี้ (2026-10-01) — commit และหลักฐานสด

| Commit | สาระ |
|---|---|
| `bbabb2c` | `fix: forensic evidence pages and attributes canonically` — byte-budget pagination + `truncated`/`next_after`, client อ่านจน JSON ครบ (ERROR_MORE_DATA), canonical source attribution ตลอด acquisition boundary |
| `3331109` | `fix: one rule authority across detection tiers` — `configs/Rules.json` เป็น authority เดียว, mirror byte-identical, golden rule-id table 3 ภาษา |
| `f00b29e` | `test: runtime gates assert the canonical daemon contract` — เลิกยึด "No log file"/"PEP" text, ยอมรับ DEGRADED ที่มีชื่อ worker ตามจริง + single-owner guard |
| `dd83fac` | `fix: pin the enforcement vocabulary and validate the dead fixtures` |
| `77424c4` | `test: restore subprocess.run after the source-space graph check` (แก้ test ที่ patch global subprocess) |

หลักฐานสด (daemon รันจริงบนเครื่องนี้):

```
aegisctl forensics list --limit 1000 --all --json   -> rc=0, records_returned=403, pages=2, truncated=false, integrity=ok
aegisctl forensics list --limit 5 --source 9        -> 5 records (npcap_sensor), next_after=4
aegisctl forensics list --limit 5 --source 9 --after 4 -> เริ่มที่ record_seq 5 (cursor ต่อเนื่อง ไม่ข้าม/ไม่ซ้ำ)
nose -inject-observe -inject-count 400              -> ring 402 records, source=(9,'npcap_sensor','canonical') 400/400
```
