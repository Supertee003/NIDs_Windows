# PEP Quarantine Status: DEFERRED

## Current State

The PEP (Policy Enforcement Point) quarantine action is currently **deferred** -- it returns a "deferred" status rather than executing immediately.

**Location**: `core/pep_enforcement_proof.zig` (G10)
**Test**: `test "executeDecision for quarantine returns deferred"`

## Why Deferred?

Quarantine requires isolating a source IP/host, which involves:
1. WFP filter installation (kernel-mode callout driver)
2. Minifilter rule injection (file system isolation)
3. Network isolation (block all traffic from source)

These operations are **not yet implemented** in the current build. The deferred queue (G10) handles retry logic:

```
executeDecision(quarantine) -> status=deferred, reason=unsupported_action
                            -> enqueue in DeferredQueue (max 64 entries)
                            -> retry up to MAX_RETRY_COUNT=3
                            -> drop after max retries
```

## Impact

- **Detection**: Unaffected (detection still produces evidence)
- **Policy**: Unaffected (policy still makes decisions)
- **Forensic**: Unaffected (forensic records the "deferred" status)
- **Enforcement**: Quarantine NOT executed (system continues without isolation)

## Resolution Path

To implement quarantine:

1. **Implement kernel IOCTL handler** in `drivers/wfp_callout/`:
   - `IOCTL_AEGIS_QUARANTINE_SOURCE` -- block all traffic from source IP
   - Reference: `core/wfp_ioctl.zig` (currently tracking-only mode)

2. **Implement minifilter rule** in `drivers/minifilter/`:
   - File system isolation for quarantined processes
   - Reference: `core/pipe_monitor.zig`

3. **Update PEP execution** in `core/rust_pep.zig`:
   - Call kernel IOCTL for quarantine action
   - Return `status=executed` on success

4. **Update proof** in `core/pep_enforcement_proof.zig`:
   - Change quarantine from "deferred" to "executed"
   - Update test expectations

## Compliance Impact

**SOC 2**: A1.3 (Recovery infrastructure) -- quarantine not required for compliance.
**ISO 27001**: A.8.23 (Web filtering) -- PEP block/alert still satisfies this control.
**NIST CSF**: RS.MI (Mitigation) -- block/rate_limit satisfy this; quarantine is additive.

**Conclusion**: Deferring quarantine does NOT break compliance. Block and rate_limit are the primary enforcement actions; quarantine is an additional isolation mechanism for severe threats.

## Tracking

- **Priority**: P2 (medium)
- **Status**: Deferred (documented)
- **Owner**: TBD
- **ETA**: Post-G22 polish
