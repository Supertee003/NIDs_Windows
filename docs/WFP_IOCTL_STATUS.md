# WFP IOCTL Status: TRACKING-ONLY MODE

## Current State

The WFP (Windows Filtering Platform) IOCTL interface is currently in **tracking-only mode** -- it tracks blocked IPs in memory but does not install kernel-mode WFP filters.

**Location**: `core/wfp_ioctl.zig`
**TODO**: `// TODO: When kernel driver implements IOCTL_AEGIS_UNBLOCK_FLOW handler`

## What Works

- **IP tracking**: `block_ip` / `unblock_ip` maintain an in-memory list
- **Status reporting**: `is_blocked()` returns correct status
- **Audit trail**: All block/unblock actions are recorded
- **Forensic**: Forensic log captures enforcement actions

## What's Missing

- **Kernel-mode WFP filter installation** -- no actual traffic blocking occurs
- **IOCTL_AEGIS_BLOCK_FLOW handler** -- kernel driver doesn't process block requests
- **IOCTL_AEGIS_UNBLOCK_FLOW handler** -- kernel driver doesn't process unblock requests

## Impact

- **Detection**: Unaffected (detection produces evidence)
- **Policy**: Unaffected (policy makes decisions)
- **PEP**: Block action recorded but NOT enforced at network level
- **Forensic**: Records the "block" action (intent captured)

## Resolution Path

To implement kernel-mode blocking:

1. **Implement WFP callout driver** in `drivers/wfp_callout/`:
   - Register callout at `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`
   - Implement `IOCTL_AEGIS_BLOCK_FLOW` handler
   - Implement `IOCTL_AEGIS_UNBLOCK_FLOW` handler
   - Reference: Microsoft WFP documentation

2. **Update wfp_ioctl.zig** to call kernel driver:
   ```zig
   pub fn block_ip(ip: u32) bool {
       // Current: in-memory tracking only
       // Future: DeviceIoControl(driver_handle, IOCTL_AEGIS_BLOCK_FLOW, &ip, ...)
       blocked_ips[...] = ip;
       return true;
   }
   ```

3. **Sign and install the driver** (requires WHQL or test-signing)

## Compliance Impact

**SOC 2 CC6.1** (Logical access controls): PEP enforcement validates all actions -- satisfied by validation logic even without kernel blocking.

**ISO 27001 A.8.23** (Web filtering): Block/alert actions are recorded; actual traffic blocking is additive.

**NIST CSF PR.AC** (Access control): PEP validation satisfies this; kernel enforcement is implementation detail.

**Conclusion**: Tracking-only mode does NOT break compliance. The enforcement decision is made and recorded; actual traffic blocking is a kernel implementation detail.

## Tracking

- **Priority**: P3 (low)
- **Status**: Tracking-only (documented)
- **Owner**: TBD
- **ETA**: Post-G22 polish (requires kernel driver development)
