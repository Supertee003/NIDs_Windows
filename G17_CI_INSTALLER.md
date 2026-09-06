# G17 — CI / Release / Installer

**Gate:** G17
**Status:** MISSING (no CI, no installer)
**Date:** 2026-09-07

## Requirement
```
CI: format, build, unit test, integration test, contract test, static analysis,
    security checks, cross-language build, Windows host regression, build manifest
Installer: install, upgrade, rollback, uninstall, service lifecycle, driver lifecycle,
           config preservation, log/forensic preservation
```

## Current State
- No `.github/workflows/`, no `appveyor.yml`, no CI config
- `build_all.bat` is manual 5-stage script
- `install_drivers.bat` is manual test-signing + `sc create`
- No installer (.msi, NSIS, Inno Setup)
- No release pipeline

## CI Design
```yaml
# .github/workflows/ci.yml (proposed)
jobs:
  zig-build:
    - zig build
    - zig test
  rust-build:
    - cargo build
    - cargo test
  cpp-build:
    - cmake --build
  integration:
    - ./test_e2e.py
  contract:
    - verify IpcEvent struct size (76 bytes)
    - verify PepDecision/PepResult ABI
```

## Installer Design
```
aegis-installer.msi:
  - Install aegis-nids.exe → C:\Program Files\AEGIS\
  - Install sec_monitor.dll → C:\Program Files\AEGIS\
  - Install aegis_ipc.dll → C:\Program Files\AEGIS\
  - Install drivers → C:\Program Files\AEGIS\drivers\
  - Create service: AEGIS-NIDS (auto-start)
  - Preserve config: Rules.json
  - Preserve logs: logs/anomalous.json
  - Uninstall: stop service, remove files, preserve logs
```

## Exit Gate
```
[x] CI design documented
[x] Installer design documented
[ ] GitHub Actions workflow file
[ ] .msi installer
[ ] Service lifecycle (install/upgrade/rollback/uninstall)
[ ] Windows host regression in CI
```
