# AEGIS NIDs Windows -- P2: Real Windows Platform

**Date:** 2026-09-02  
**Scope:** WFP production path, HIDS/minifilter, unified events, Rust enforcement, service lifecycle, secure installer, recovery/rollback

## P2 Audit Results

| Component | Status | Gap |
|---|---|---|
| WFP driver (aegis_wfp.sys) | EXISTS (4 C files + .inf) | Driver source is complete; Zig bridge (wfp_ioctl.zig, 585 lines) has IOCTL definitions; NOT compiled/installed in production |
| Minifilter driver (aegis_minifilter.sys) | EXISTS (5 C files + .inf) | Same as WFP: source complete, not deployed |
| wfp_ioctl.zig (Zig bridge) | EXISTS (585 lines) | IOCTL definitions + DeviceIoControl calls implemented; needs device open/close lifecycle testing |
| hids_engine.zig | EXISTS (899 lines) | Event types defined (file_create, registry_modify, process_create, etc.); produces Canonical Events |
| rust_pep.zig (enforcement) | PARTIAL (886 lines) | Has in-memory blocklist simulation; comment says "Future: actual Rust FFI calls to rust_shield for WFP blockIp()"; needs real WFP IOCTL call from Rust |
| Service lifecycle | NOT STARTED | No Windows Service (.sc) wrapper, no service recovery |
| Secure installer | PARTIAL | NSIS installer exists; no code signing, no secure permissions |
| Recovery/rollback | NOT STARTED | No rollback package, no service recovery on failure |

## P2 Requirements

### 2.1 WFP Production Path

The WFP driver (aegis_wfp.sys) must be:
1. Compiled with WDK (Windows Driver Kit)
2. Signed with a test certificate (for development) or WHQL (for production)
3. Installed via `sc create` or NSIS installer
4. Started via `sc start aegis_wfp`
5. Connected to core via wfp_ioctl.zig (IOCTL bridge)
6. Health-monitored via IOCTL_AEGIS_GET_STATS

Prerequisites:
- WDK (Windows Driver Kit) installed
- Visual Studio Build Tools
- Admin rights for driver installation

Build steps:
```
cd drivers/wfp_callout
build.bat  (uses WDK)
signtool sign /fd SHA256 /f test.pfx aegis_wfp.sys
sc create aegis_wfp type= kernel binPath= aegis_wfp.sys
sc start aegis_wfp
```

Integration with core:
```
core/wfp_ioctl.zig:
  1. OpenDevice("\\\\.\\aegis_wfp") -- opens driver device
  2. DeviceIoControl(IOCTL_AEGIS_READ_EVENTS) -- reads ring buffer events
  3. DeviceIoControl(IOCTL_AEGIS_BLOCK_FLOW, ip) -- blocks IP via WFP
  4. DeviceIoControl(IOCTL_AEGIS_GET_STATS) -- gets driver statistics
  5. CloseDevice() -- closes on shutdown
```

### 2.2 HIDS / Minifilter Production Path

The minifilter driver (aegis_minifilter.sys) must be:
1. Compiled with WDK
2. Signed and installed
3. Started via `sc start aegis_minifilter`
4. Connected to core via minifilter_reader.zig (pipe-based)
5. Events flow: minifilter -> named pipe -> minifilter_reader.zig -> hids_engine.zig -> Canonical Event

Minifilter event types (from hids_engine.zig):
- process_create
- process_exit
- file_create
- file_write
- service_change
- registry_modify
- network_connect

### 2.3 Host/Network Unified Events

Both WFP (network) and HIDS (host) produce the same Canonical Event schema:
- Same magic, version, event_id counter
- Same timestamps, source_id, session_id
- Different EventSource: wfp_sensor vs minifilter

Correlation between network and host events:
- By session_id (if both have the same flow)
- By src_ip + timestamp proximity
- By rule_id (if same rule matched both network and host)

### 2.4 Rust Enforcement Adapter

Current rust_pep.zig uses in-memory blocklist (simulation).
Real enforcement requires:

```rust
// shield/src/lib.rs (future)
#[no_mangle]
pub extern "C" fn aegis_block_ip(ip: u32, reason: u32) -> i32 {
    // Call WFP IOCTL from Rust
    // OpenDevice("\\\\.\\aegis_wfp")
    // DeviceIoControl(IOCTL_AEGIS_BLOCK_FLOW, &ip)
    // Return: 0=success, -1=error
}

#[no_mangle]
pub extern "C" fn aegis_unblock_ip(ip: u32) -> i32 {
    // Call WFP IOCTL from Rust
}

#[no_mangle]
pub extern "C" fn aegis_get_stats() -> i32 {
    // Call WFP IOCTL from Rust
}
```

The Zig core would call these via FFI:
```zig
// core/rust_pep.zig (updated)
const shield = @import("bridge_init.zig");

// Instead of in-memory blocklist:
// shield.aegis_block_ip(ip, reason_code);
```

### 2.5 Service Lifecycle

Each component should run as a Windows Service:
- `aegis-core` service (zig-out/bin/aegis-nids.exe)
- `aegis-brain` service (python brain/windows_brain.py)
- `aegis-nose` service (dist/nose_dashboard.exe --headless)
- `aegis-aggregator` service (go/aggregator/aegis-aggregator.exe)

Service recovery on failure:
```bat
sc failure aegis-core reset= 86400 actions= restart/5000/restart/10000/restart/30000
sc failure aegis-brain reset= 86400 actions= restart/5000/restart/10000/restart/30000
```

Service wrapper options:
1. Use NSSM (Non-Sucking Service Manager) for Python/Go components
2. Use native Windows Service for Zig core (add SCM integration)

### 2.6 Secure Installer

NSIS installer (installer/aegis_nids_installer.nsi) requires:
1. Code signing: signtool sign /fd SHA256 /f cert.pfx installer.exe
2. Driver signing: signtool sign /fd SHA256 /f cert.pfx aegis_wfp.sys
3. Secure permissions:
   - $INSTDIR: Administrators:Full, SYSTEM:Full, Users:Read+Execute
   - config\: Administrators:Full, SYSTEM:Full (no Users access)
   - logs\: Administrators:Full, SYSTEM:Full, Service:Write
4. Verify prerequisites: WDK, Python, .NET, driver service

### 2.7 Recovery/Rollback

Rollback scenarios:
1. Driver installation fails -> sc delete aegis_wfp, remove files
2. Service fails to start -> sc stop, check Event Log, rollback to previous version
3. Config invalid -> aegisctl policy reject update, keep last known-good
4. PEP unavailable -> no enforcement, record failure, fail-safe

## P2 Exit Conditions

- [ ] WFP driver compiled, signed, installed, and passing IOCTL tests
- [ ] Minifilter driver compiled, signed, installed
- [ ] wfp_ioctl.zig successfully reads events from driver
- [ ] hids_engine.zig processes minifilter events as Canonical Events
- [ ] Rust PEP calls WFP IOCTL for real enforcement (not simulation)
- [ ] Services registered with recovery actions
- [ ] Installer signed with valid certificate
- [ ] Rollback procedure tested
