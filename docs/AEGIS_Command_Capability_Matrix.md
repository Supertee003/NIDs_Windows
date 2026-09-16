# AEGIS Command Center Capability Matrix

เอกสารนี้แยกความสามารถตาม implementation ที่ตรวจได้จริง ไม่ใช้ชื่อ command เป็นหลักฐานว่า feature ทำงานครบ

## สถานะของคำสั่ง

| Group/option | สถานะ | แหล่งข้อมูลหรือผลจริง | คำแนะนำ |
|---|---|---|---|
| `status` | พร้อมใช้งาน | Control Center subsystem payload | ใช้ดู component/PID |
| `status --json` | พร้อมใช้งาน | JSON contract | ใช้ automation |
| `health` | พร้อมใช้งาน | `system.health` | ไม่ใช่ strict gate โดย default |
| `health --strict` | พร้อมใช้งาน | exit 1 เมื่อ degraded | ใช้ CI/preflight |
| `readiness` | พร้อมใช้งาน | worker gate + subsystem gate | ใช้ตัดสิน readiness |
| `doctor` | พร้อมใช้งาน | structured worker diagnostics | ใช้แก้ native/runtime issue |
| `snapshot` | พร้อมใช้งาน | health + metrics + forensic | ใช้ Dashboard/automation |
| `metrics` | พร้อมใช้งาน | `metrics.snapshot` | ต้องมี Control Center |
| `version` | พร้อมใช้งานบางส่วน | component registry ใน CLI | ยังไม่ใช่ binary ABI fingerprint |
| `start --all` | พร้อมใช้งานตาม artifact | process launcher definitions | ต้องตรวจ health หลัง start |
| `rules list/show/validate` | พร้อมใช้งาน | canonical `configs/Rules.json` | read-only |
| `rules reload` | พร้อมใช้งานเมื่อ daemon pipe | `rules.reload` | ต้อง validate ก่อน |
| `rules add/update/delete` | พร้อมใช้งาน local file | atomic local write | ต้อง reload หลังแก้ |
| `events count/stats/tail` | พร้อมใช้งาน | `logs/aegis_core.ndjson` | เป็น evidence view |
| `events tail --follow` | พร้อมใช้งาน | polling event log | หยุดด้วย Ctrl+C |
| `forensics verify/list` | พร้อมใช้งานผ่าน Control Center | forensic control commands | ใช้ canonical plural form |
| `forensic show/search/export` | พร้อมใช้งาน local evidence | event log reader | ไม่ใช่ hash-chain verification |
| `tui` menu | พร้อมใช้งานแบบ compatibility | Control Center + fallback process scan | ใช้ `Control Center` source เป็นหลัก |
| `console --role operator` | พร้อมใช้งาน | Pro control surface, read-only | ใช้เป็นหน้าหลักของ Operator |
| `console --role admin` | พร้อมใช้งานแบบ guarded | start/stop/reload ผ่าน role + Administrator check | ใช้จาก elevated shell |
| `console --mode mouth-nose` | พร้อมใช้งาน | Control Center health/data-plane | แสดง path ไม่รับรอง enforcement เอง |
| `tui --mode dashboard` | พร้อมใช้งาน | explicit polling interval | ใช้ `--once` ลด refresh |
| `web` | พร้อมใช้งานเมื่อ Rust binary/deps | Rust egui dashboard | ต้อง build บน Windows |
| `graph` | พร้อมใช้งานเมื่อ Python deps | canonical event log | source → rule → AEGIS |
| `authority` | พร้อมใช้งาน source audit | static invariant check | ไม่ใช่ runtime enforcement proof |
| `block add/remove/clear` | unavailable | ไม่มี PEP/WFP postcondition | ใช้ `list` ได้เฉพาะดู local state |
| `quarantine add/remove` | unavailable | ไม่มี PEP/WFP postcondition | ใช้ `list` ได้เฉพาะดู local state |
| `enforce enable/disable/push` | unavailable | ไม่มี PEP runtime postcondition | ใช้ `status` ดู local stateเท่านั้น |
| `policy enable/disable/reload` | unavailable | ไม่มี active policy postcondition | ใช้ `list/show` ดูข้อมูลเท่านั้น |
| `simulate attack/packet/flood/replay` | unavailable | ใช้ event generator ที่ควบคุมได้แทน | ไม่รายงาน success ปลอม |
| `canary run/status/report` | unavailable | end-to-end runner ยังไม่เชื่อม | ไม่ใช่ end-to-end canary |
| `alerts` | unavailable | alert query ยังไม่เชื่อม | ใช้ events/forensics แทน |
| `bridge` | unavailable | bridge diagnostic ยังไม่เชื่อม | ใช้ health/snapshot แทน |
| `iptest` | unavailable | throughput probe ยังไม่เชื่อม | ไม่ใช้เป็น performance evidence |
| `dashboard` | summary only | subsystem/DEFCON summary | ใช้ `aegis web` แทน |

## คำสั่งที่ควรใช้เป็นมาตรฐาน

```powershell
.\scripts\aegis.ps1 status --json
.\scripts\aegis.ps1 health --json
.\scripts\aegis.ps1 readiness --pretty
.\scripts\aegis.ps1 doctor
.\scripts\aegis.ps1 snapshot
.\scripts\aegis.ps1 rules validate
.\scripts\aegis.ps1 metrics
.\scripts\aegis.ps1 forensics verify --json
```

## คำสั่งที่ควรหลีกเลี่ยงใน Production

ไม่ควรใช้ `simulate`, `canary`, `alerts`, `bridge`, `iptest`, `enforce push`, `block`, `quarantine` หรือ `policy` เป็นหลักฐานว่า native enforcement ทำงานครบ เพราะบางคำสั่งยังเป็น local state หรือ placeholder และไม่แสดง postcondition จาก PEP/WFP

คำสั่งเหล่านี้คืน JSON สถานะ `available: false` และ exit code `4` แทนการพิมพ์ข้อความสำเร็จโดยไม่มี postcondition

## TUI options

```powershell
python scripts\aegis_console.py --help
python scripts\aegis_console.py --mode menu
python scripts\aegis_console.py --mode health
python scripts\aegis_console.py --mode dashboard --interval 2
python scripts\aegis_console.py --mode dashboard --interval 5 --once
```

Pro Console:

```powershell
.\scripts\aegis.ps1 console --role operator
.\scripts\aegis.ps1 console --role admin
.\scripts\aegis.ps1 console --mode snapshot
.\scripts\aegis.ps1 console --mode mouth-nose
```

`--mode dashboard` จะ refresh ตาม interval ที่ระบุ ค่า default คือ 2 วินาที ไม่ได้เป็น loop ที่ไม่มีการควบคุมอีกต่อไป `--once` จะแสดง snapshot เดียวและรอ Enter

## Readiness interpretation

เมื่อผลเป็น:

```json
{
  "state": "RUNNING",
  "worker_gate": true,
  "overall_gate": false,
  "degraded_components": [
    {"name": "cpp", "error": "windows_telemetry_not_ready"}
  ]
}
```

ให้สรุปว่า event pipeline พร้อม แต่ production/native gate ยังไม่ผ่าน ห้ามเริ่ม Controlled Attack Test จนกว่าจะมี risk acceptance สำหรับ degraded component หรือแก้ native adapter แล้ว

## Design rule

Command ที่ทำ mutation ต้องมี postcondition ที่ตรวจได้จาก Control Center หรือ PEP/WFP evidence หากยังไม่มี postcondition ให้แสดงสถานะ unavailable อย่างชัดเจน ไม่ควรรายงาน `OK` จากการเขียนไฟล์ local เพียงอย่างเดียว

## References

[1]: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_exit_codes "Microsoft PowerShell exit code documentation"
