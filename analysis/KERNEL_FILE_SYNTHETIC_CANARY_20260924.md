# KERNEL_FILE Synthetic Rule Canary

**Status:** `PASS`

This scan compiles the configured R1001-R1005 regexes against in-memory Windows path fixtures only. It performs no file I/O against the fixture paths and does not invoke enforcement.

| Rule | Positive path | Positive match | Negative match |
|---|---|---:|---:|
| `R1001` | `C:\Windows\System32\drivers\aegis-proof.sys` | `True` | `False` |
| `R1002` | `C:\Temp\document.locked` | `True` | `False` |
| `R1003` | `C:\Users\Proof\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\aegis.lnk` | `True` | `False` |
| `R1004` | `C:\Windows\System32\aegis-proof.dll` | `True` | `False` |
| `R1005` | `C:\Windows\System32\drivers\etc\hosts` | `True` | `False` |

## Findings

- All five configured regexes matched their positive fixture and rejected their negative fixture.

## Sensor boundary note

The canary proves rule-pattern behavior only. The FIM adapter now carries the active watch-root identity into the canonical file event; full E2E qualification still requires a Windows host run with evidence capture and no enforcement request.

