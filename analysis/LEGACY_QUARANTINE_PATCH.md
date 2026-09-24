# Legacy Quarantine Patch

## Decision

The active AEGIS enforcement contract is flow-specific and receipt-aware. IP-only mutation is not an enforcement path. Legacy exports may remain in the Rust/C DLL for ABI compatibility, but they must be hard-fail stubs and must never be required for provider readiness.

## Changes in this patch

The Zig PEP binding no longer imports or exposes `aegis_pep_unblock_ip` as an active operation. Exact cleanup uses only `aegis_pep_unblock_filter(filter_id, ...)`.

The T8 structural test now verifies both sides of the compatibility decision: the Rust legacy symbol may exist, but its implementation must explicitly state that it never mutates WFP, while the exact filter cleanup symbol must also exist.

The WFP contract test now checks the packed `AEGIS_WFP_FLOW_REQUEST`, `AEGIS_WFP_FLOW_RESPONSE`, `UINT64 filter_id`, and exact `aegis_wfp_ioctl_unblock_filter` path instead of asserting the old IPv4 cleanup payload.

The Python control API and advisory brain wrappers no longer submit `target_port=0` or a non-numeric rule name to the receipt-aware request function. They return a safe deferred/false result unless an exact destination port and numeric policy identity are supplied. This preserves detection while preventing an invalid enforcement request from being formed.

## Current safety state

```text
legacy IP-only mutation       = quarantined
active cleanup identity      = exact filter_id
provider readiness dependency = new flow/filter symbols only
prevention_gate               = closed
host_effect_capable           = false
```

## Remaining production blocker

The current handler correctly refuses `enforcement.block` while `g_prevention_gate_open` is false. Before any gate can be opened, `PepEnforcer.enforceFlow` and the control handler still need an independent provider read-back that proves the exact filter exists with the expected owner, layer, action, and flow scope. A provider-returned `filter_id` alone must never become `status=ENFORCED`.

## Host validation

Run the corrected Python orchestrator on the Windows Host. The sandbox does not have the repository's pytest environment, so targeted Python tests were not executed locally; Python syntax and whitespace validation passed.
