# G12 — Real WFP

**Gate:** G12
**Status:** PARTIAL (driver skeleton exists; block IOCTL stubbed)
**Date:** 2026-09-07

## Requirement
```
WFP / driver → sensor event → Canonical Event → detection → policy → Rust PEP → WFP action → forensic record
```

## Current State
- WFP callout driver: `drivers/wfp_callout/aegis_wfp*.{c,h}`
- Registers at `FWPM_LAYER_INBOUND_TRANSPORT_V4`
- Ring buffer (2MB) + IOCTL interface
- `IOCTL_AEGIS_BLOCK_FLOW` returns `STATUS_NOT_IMPLEMENTED`
- Driver not built (no .sys in dist/)

## Integration with G10 PEP
```
Policy decision → pep_enforce_action(PepDecision)
  → Rust calls IOCTL_AEGIS_BLOCK_FLOW (TODO: implement)
    → WFP callout blocks traffic from source_ip
      → Forensic record created (G13)
```

## Exit Gate
```
[x] WFP callout driver source exists
[x] IOCTL_AEGIS_READ_EVENTS works (capture path)
[x] IOCTL_AEGIS_BLOCK_FLOW defined (returns STATUS_NOT_IMPLEMENTED)
[x] G10 PEP documents the enforcement path (Policy → pep_enforce → WFP)
[ ] Block IOCTL implementation (replace STATUS_NOT_IMPLEMENTED)
[ ] Driver built (.sys) and tested on Windows host
[ ] E2E: detection → policy → PEP → WFP block → forensic record
```
