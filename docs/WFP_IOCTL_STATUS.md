# WFP IOCTL & Enforcement Status: IMPLEMENTED (lab-gated)

Updated 2026-10-19. Supersedes the earlier "tracking-only" description
(see History below).

## Current state

The WFP stack has two implemented layers:

1. Kernel driver `drivers/wfp_callout/` (`aegis_wfp.sys`; sources
   `aegis_wfp.c` / `aegis_wfp_callout.c` / `aegis_wfp.h`; device
   `\\.\AegisWfpDevice`):
   - registers an inbound IPv4 callout at `FWPM_LAYER_INBOUND_TRANSPORT_V4`
     that copies packet payloads into a 2 MB ring for telemetry. The copy
     path is observe-only / fail-open by design - nothing blocks there;
   - processes the full control IOCTL set:
     `IOCTL_AEGIS_READ_EVENTS` (read), `IOCTL_AEGIS_BLOCK_FLOW` (write),
     `IOCTL_AEGIS_GET_STATS` (read), `IOCTL_AEGIS_UNBLOCK_FLOW` (write),
     `IOCTL_AEGIS_QUERY_FILTER` (read);
   - `IOCTL_AEGIS_BLOCK_FLOW` installs an exact-flow WFP filter
     (remote IPv4 + port + protocol) with `FWP_ACTION_BLOCK` at
     `FWPM_LAYER_ALE_AUTH_CONNECT_V4` for outbound (direction 0) or
     `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` for inbound capture
     (direction 1), and returns its `filter_id`; unblock/query operate
     on that id. The query input names the direction so an outbound
     read-back can never attest an inbound filter.
2. User-mode boundary:
   - `src/policy/wfp_ioctl.zig` is READ-ONLY telemetry transport
     (PEP-001): privileged block/unblock is prohibited in this module.
     All privileged actions MUST go through `src/policy/pep_bindings.zig`
     to the Rust PEP;
   - `src/windows/wfp_ioctl.c` (compiled to `aegis_wfp_user.dll` by the
     root CMakeLists.txt) is the user-mode IOCTL bridge that issues
     block/unblock/query requests to the driver;
   - `rust-src/lib.rs` (`wfp_adapter` + `adapter_cache`) is the sole
     enforcement authority: it loads `aegis_wfp_user.dll`, requires the
     exports `aegis_wfp_ioctl_open/block_flow/unblock_filter/query_filter`
     (direction-aware `query_filter_dir` is required for inbound
     attestation; telemetry-only `read_events`/`close` are optional), and executes
     block / quarantine decisions as exact-flow filters via
     `IOCTL_AEGIS_BLOCK_FLOW`, with an exact-filter read-back
     (`IOCTL_AEGIS_QUERY_FILTER`) postcondition. When the adapter is
     absent it fails closed (`DECISION_ESCALATE`, reason 4) - never open.

## What gates enforcement today (by design)

- The prevention gate (`-Dlab-prevention-gate`, default false) is the
  master switch for host mutation; every default/production build refuses
  block/quarantine/rate_limit at the Zig boundary before the provider.
- The live production daemon currently runs detection-only (pre-V6 binary;
  operator redeploy pending) and reports `blocks delta 0`.
- The kernel drivers are test-signed until production signing (EV
  certificate / HLK) lands.
- End-to-end live enforcement proof is the operator lab sequence
  RB-012 -> RB-013 on an isolated lab VM (G2).

## What this replaces (history)

The previous version of this file described the "tracking-only" era:
an in-memory IP list in a legacy `wfp_ioctl` module under the old `core`
tree (that tree no longer exists) with no kernel filter installation.
That description stopped being true once the callout driver, the IOCTL
set, and the Rust PEP adapter path landed (NIC-001 / EVT-231 / EVT-232
era; PEP-001 split).

## Compliance impact (unchanged intent)

- **SOC 2 CC6.1** (logical access controls): PEP validation + audit trail.
- **ISO 27001 A.8.23** (web filtering): block/alert actions are decided,
  recorded, and enforced through the gated WFP path.
- **NIST CSF PR.AC** (access control): the Rust PEP is the sole authority;
  kernel IOCTLs are reachable only through it (PEP-001).
