# Windows Toolchain Inventory

## Evidence from the latest Windows build log

| Tool or dependency | Evidence | Status |
|---|---|---|
| CMake | Configure and generate completed | Available |
| Windows SDK | SDK 10.0.28000.0 selected for Windows 10.0.26200 | Available |
| MSBuild | Version 17.14.51 | Available |
| Zig | Direct build reached Registry source compilation | Available; source error was exposed |
| Rust PEP import library | `target/release/aegis_pep.lib` was found by direct link command | Available |
| Npcap SDK | `wpcap.lib` and `Packet.lib` were verified present | Available |
| ETW helper | CMake produced `build/Release/aegis_etw_helper.dll` and `.lib` | Built; warnings corrected in source |
| FIM helper | CMake produced `build/Release/aegis_fim_helper.dll` and `.lib` | Built; warnings corrected in source |
| WFP user helper | CMake produced `build/Release/aegis_wfp_user.dll` | Built |
| WFP kernel driver/device | Not proven by build log | Must verify service/device at runtime |

## Corrections made after inventory

The Registry Win32 event handle declaration now correctly uses an optional handle, matching `CreateEventA` failure semantics. ETW and FIM native helpers include the correct allocation header; ETW uses `PROCESSTRACE_HANDLE` for `OpenTraceW`/`ProcessTrace`/`CloseTrace`. Zig build configuration now searches both `target/helpers` and the actual CMake output directory `build/Release`.

## Remaining machine-level verification

Run these commands in an elevated PowerShell session before declaring all gates ready:

```powershell
sc.exe query type= driver state= all | findstr /I Aegis
Get-Service | Where-Object { $_.Name -match 'Aegis|WFP|ETW|FIM' }
fltmc filters | findstr /I Aegis
pnputil /enum-drivers | findstr /I Aegis
```

The named device must also be testable by the daemon as `\\.\AegisWfpDevice`; a DLL being present is not proof that the kernel device is registered.
