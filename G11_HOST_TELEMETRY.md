# G11 — Real Windows Host Telemetry

**Gate:** G11
**Status:** DOCUMENTED (implementation requires Windows host)
**Date:** 2026-09-07

## Requirement
```
ETW: StartTraceW → EnableTraceEx2 → OpenTraceW → ProcessTrace → EventRecordCallback → Canonical Event
FIM: CreateFileW → ReadDirectoryChangesW → parse event → Canonical Event
Registry: RegOpenKeyExW → RegNotifyChangeKeyValue → parse change → Canonical Event
```

## Current State
- Minifilter driver skeleton exists (file IRP + process callbacks)
- `minifilter_reader.zig` is STUB (no FilterGetMessage binding)
- `pipe_monitor.zig` is STUB (no FindFirstFileW binding)
- No ETW integration

## Architecture (designed, not yet implemented)
```
ETW Kernel-Process provider → EventRecordCallback → EtwEventRecord → Canonical IpcEvent
ETW Kernel-File provider     → EventRecordCallback → EtwEventRecord → Canonical IpcEvent
ETW Kernel-Registry provider → EventRecordCallback → EtwEventRecord → Canonical IpcEvent
ReadDirectoryChangesW        → FILE_NOTIFY_INFORMATION → Canonical IpcEvent
RegNotifyChangeKeyValue       → RegChangeInfo → Canonical IpcEvent
```

All events use the G2 canonical IpcEvent struct (76 bytes).

## Exit Gate
```
[x] Architecture designed (ETW → IpcEvent mapping documented)
[x] Minifilter driver source exists (drivers/minifilter/*.c)
[x] pipe_monitor.zig classified as SCAFFOLD
[x] minifilter_reader.zig classified as SCAFFOLD
[ ] Windows host test: events appear in AEGIS runtime
[ ] ETW real-time integration (Phase 37 Ext 5 provides framework)
```

**Note:** Full implementation requires Windows host with WDK. The architecture
is documented; code implementation is Phase 37 Ext 4/5 scope (already designed
in `/home/z/my-project/download/`).
