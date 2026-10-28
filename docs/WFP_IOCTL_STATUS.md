# WFP IOCTL & Enforcement Status: IMPLEMENTED (lab-gated)

Updated 2026-10-19; arbitration live-state note appended 2026-10-26
(E5-C arbiter host proof). Supersedes the earlier "tracking-only" description
(see History below).

## Current state

The WFP stack has two implemented layers:

1. Kernel driver `drivers/wfp_callout/` (`aegis_wfp.sys`; sources
   `aegis_wfp.c` / `aegis_wfp_callout.c` / `aegis_wfp.h`; device
   `\\.\AegisWfpDevice`):
   - registers **two** IPv4 transport callouts: inbound at
     `FWPM_LAYER_INBOUND_TRANSPORT_V4` and outbound at
     `FWPM_LAYER_OUTBOUND_TRANSPORT_V4`. Both copy L4 payload bytes into the
     same 2 MB ring using the same 48-byte record; the header `direction`
     byte (0=inbound, 1=outbound) is the discriminator. Inbound transport
     data starts at payload; outbound starts at the TCP/UDP header, which the
     producer validates and strips (TCP data offset / UDP length) before copy.
     Malformed or unsupported outbound transport data keeps the event header,
     records zero payload bytes, and remains fail-open. The copy path is
     observe-only / fail-open by design - nothing blocks there;
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

## Network acquisition states (PHASE-6)

Npcap (via Go Nose) and the WFP kernel ring cannot both own detection
ingress: two sources duplicate event identities, double flow packet/byte
accounting, and double rate-rule observations (DP-10). The runtime states
the owner explicitly (`src/capture/source_arbiter.zig`) and reports it in
`queue.stats` under `wfp.mode` / `wfp.reason` / `wfp.shadow_rows`:

| mode | condition | Npcap rows | kernel rows |
|---|---|---|---|
| `npcap_primary` | Nose connected + ready and producing | submitted | drained, counted as shadow, NOT submitted |
| `kernel_fallback` | Nose absent, or Nose submitted-frame count stalled >= 10 s while the kernel keeps seeing rows | submitted if present | submitted (inbound + outbound) |
| `split_lab` | `AEGIS_CAPTURE_SPLIT=1` opt-in, disjoint interfaces only | submitted | submitted |
| `none` | neither source available | - | - |

The kernel ring is always drained, even in shadow mode: a 2 MB ring must
never overflow because the consumer disagreed with the mode. Shadow rows
are evidence the kernel saw traffic the packet path did not deliver, and
`g_wfp_shadow_rows` makes that countable instead of silent. Takeover is
evidence-driven (kernel rows while the Nose submitted-frame counter stands still), so
an idle network never flaps the mode; a resumed Nose stands the kernel
back down before the next record is submitted.

## What gates enforcement today (by design)

- The prevention gate (`-Dlab-prevention-gate`, default false) is the
  master switch for host mutation; every default/production build refuses
  block/quarantine/rate_limit at the Zig boundary before the provider.
- The runtime daemon file is pinned at SHA-256
  `464E765BAED95C47C0ECCABCC4C47EF682D96762A8C44B329B7B536AB656BC61`; the
  runtime Nose file is `735E2B8A9A6836E7407C20DC152CEB50164304CA2879AF14DEA8277F350C5C2E`.
  E5-A replaced the prior G2 candidate `95C7E749…F8CCE03` with the signed
  O2 candidate `49E65BB12B4FC164F0B0C255AC75CDFA096F17AC77B056586BF16891FCDABE8C`
  (unsigned build `7EDE4DCD…`); AegisWfp and AegisNids returned RUNNING. This
  proves deployment only; O2 outbound capture still lacks valid host functional
  evidence.
  The corrected E5-C host proof observed `npcap_primary → kernel_fallback →
  npcap_primary`, with Nose frames and kernel shadow rows advancing. The
  prevention gate remained closed and `host_effect_capable=false` throughout.
  The earlier run that launched Nose without `-capture` remains recorded as
  PARTIAL; see `admin-evidence/e5-host-proof-20261026/E5C-ARBITER-E2E-20261026.md`.
- The kernel drivers are test-signed until production signing (EV
  certificate / HLK) lands.
- Current source adds outbound TCP/UDP transport-header validation/stripping
  before the bounded ring payload copy (source commit `26513a2`, unsigned build
  SHA-256 `E0C368C1…`). This candidate has not been signed or deployed; the
  live driver remains the prior signed O2 image until the E5 rollback-wrapped
  operator proof completes.

- 2026-10-28: the direct-PEP G2 duplicate-filter proof re-ran against this deployed O2 signed image (49E65BB1…) with
  every DUP marker true (filter id 7167880 reused, unblock rc=0, absence present=0, no skip); see
  admin-evidence/g2-dupfilter-20261028. The O2 outbound E5 direction proof remains open until the signed offset
  candidate replay (29ED40E3…D55, from unsigned E0C368C1…) passes.
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
