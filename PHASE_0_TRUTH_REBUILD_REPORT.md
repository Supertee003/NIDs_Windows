# Phase 0 — Truth Rebuild Report

**วันที่:** 17 กันยายน 2026  
**Current HEAD:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**สถานะ:** `PARTIAL — provenance mechanism improved; truth set not yet valid`

## สิ่งที่ดำเนินการ

1. ปรับ `tools/create_manifest.py` ให้ค้นหา repository root จากตำแหน่ง script แทนการใช้ `D:/NIDs_Windows` แบบ hard-code
2. เปลี่ยน manifest generator ให้ดึง full current HEAD ด้วย `git rev-parse HEAD`
3. เพิ่มทั้ง `head_sha` แบบเต็มและ `source_commit` แบบย่อใน `runtime_manifest.json`
4. สร้าง `tools/rebuild_truth.py` เป็น canonical orchestrator สำหรับ:
   - regenerate `inventory.json` และ `reference_map.json`
   - regenerate `runtime_manifest.json`
   - ตรวจ JSON structure
   - เรียก `tools/truth.py verify`
   - บันทึก unresolved artifacts โดยไม่แก้ SHA แบบ manual
5. รัน orchestrator สองรอบและบันทึกผล JSON ที่ `PHASE_0_TRUTH_REBUILD_REPORT.json`

## ผลที่ผ่าน

- `tools/create_manifest.py` syntax ผ่าน
- `runtime_manifest.json` ถูกสร้างจาก current HEAD
- `runtime_manifest.json` มี `head_sha` เต็มตรงกับ current HEAD
- `runtime_manifest.json` ผ่าน source provenance check ของ `tools/truth.py`
- `inventory.json` และ `reference_map.json` regenerate ได้
- JSON validation ของ artifacts ที่มีอยู่ผ่านโครงสร้าง JSON

## Unresolved artifacts

รายการต่อไปนี้ยังทำให้ `tools/truth.py verify` เป็น `TRUTH_INVALID`:

```text
SYSTEM_MAP.json
FLOW_MAP.json
AUTHORITY_MAP.json
CONTRACT_MAP.json
EVIDENCE_INDEX.json
build_truth.json
build_manifest.json
AI_CONTEXT.md
```

สาเหตุหลักคือยังไม่พบ canonical current-head generator ที่เชื่อถือได้สำหรับ machine maps/evidence ชุดนี้ และ `build_manifest.json` ยังใช้ schema/provenance จาก revision เดิม การเติมหรือเปลี่ยนค่า SHA โดยตรงจะทำให้หลักฐานไม่ถูกต้อง จึงยังไม่ได้ทำ

## คำสั่ง canonical ที่เพิ่ม

```text
python tools/rebuild_truth.py
```

คำสั่งจะคืน exit code `1` เมื่อ truth set ยังไม่ valid และจะเขียนผล machine-readable ที่:

```text
PHASE_0_TRUTH_REBUILD_REPORT.json
```

## ระดับหลักฐาน

- **E1:** source inspection และ generator implementation
- **E2:** JSON/provenance verification และ successful generator execution
- **ยังไม่มี E3–E5:** ยังไม่ได้พิสูจน์ runtime Windows, SCM, named pipe หรือ release artifact

## ขั้นตอนถัดไปของ Phase 0

1. หา/สร้าง canonical generator สำหรับ `SYSTEM_MAP`, `FLOW_MAP`, `AUTHORITY_MAP`, `CONTRACT_MAP` และ `EVIDENCE_INDEX`
2. กำหนด schema provenance เดียวกันให้ทุก map
3. ปรับ `build_manifest` ให้สร้างจาก actual artifact set และ current source commit
4. ปรับ `build_truth` และ `AI_CONTEXT` ผ่าน generator เดียวกัน
5. รัน `python tools/rebuild_truth.py` จนได้ `TRUTH_VALID`
6. จากนั้นจึงเริ่ม Phase 1 runtime foundation

## ข้อควรระวัง

รายงานนี้ไม่ได้ประกาศว่า Phase 0 เสร็จสมบูรณ์ การปรับปรุงที่ทำสำเร็จคือ **กลไก provenance ของ runtime manifest และ canonical orchestration** เท่านั้น ส่วน machine maps และ release truth ยังต้องสร้าง generator ที่ถูกต้องก่อน
