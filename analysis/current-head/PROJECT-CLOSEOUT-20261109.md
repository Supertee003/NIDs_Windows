# AEGIS NIDS Windows — Project Closeout Record (2026-11-09)

Records state at build source `bb5d780dd60d85dedf0444532afedb72e84ebee1`.
This is a **status and decision record**, not a release claim and not an E5/E7
claim. It closes nothing by itself and asserts no host capability.

## Product boundary (unchanged, authoritative)

Detection-only. `prevention_gate=closed`, `tier3_enforcing=false`,
`host_effect_capable=false`. No production path may add an AEGIS-owned
`FWP_ACTION_BLOCK` filter, mutate traffic, or emit `host_effect_confirmed=true`.
Policy intent such as "would block" is evidence context only.

## Gate state at this source commit

| Gate | State | Evidence level | Basis |
|---|---|---|---|
| Canonical unit suite | PASS | E2 | 2,069 passed / 10 skipped / 0 failed, fresh cache at `bb5d780` |
| Test-scope ratchet (#27) | PASS / closed | E2 | `TEST-SCOPE-001-E2-20261109` |
| XDR advisory authority (#26) | PASS / closed | E2 | `XDR-AUTHORITY-RECONCILE-001-E2-20261109` |
| Truth artifacts | VALID | E1 | `truth.py verify` TRUTH_VALID at `bb5d780`, clean worktree |
| Evidence summary | VALID | E1 | `check_summary.py` SUMMARY_VALID |
| Release artifact hashes | PASS | E1 | `verify_release.ps1` 9/9 vs `manifest.json` |
| Windows deploy of current source | NOT DONE | — | installed `aegis_nids.exe` = `438F9D5F...` (source `318a10a`) |
| Kernel drivers loaded | NOT DONE | — | `AegisWfp` / `AegisMinifilter` STOPPED (DEMAND_START) since boot |
| Signed release (E7) | NOT DONE | — | no signing key custody; the only `E7` entry is historical `EVT-220` |

## Remaining STOP-THE-LINE issues and why they are not closed here

### #25 — WFP/PEP host-blocking source paths vs detection-only scope

The source still contradicts the confirmed product decision:

- `drivers/wfp_callout/aegis_wfp.c` still implements `IOCTL_AEGIS_BLOCK_FLOW`
  and creates `FWP_ACTION_BLOCK` filters (line ~1164); capture classify already
  returns `FWP_ACTION_PERMIT`, which is correct and must stay.
- `rust-src/lib.rs::aegis_pep_enforce` still routes BLOCK/QUARANTINE through
  `adapter.block_flow` and mints a filter receipt.
- `src/control/handler_registry.zig` still registers
  `enforcement.block/quarantine/unblock`; they are gated closed but not
  hard-refused.
- `src/pipeline/event_processor.zig` can project `enforced` /
  `host_effect_confirmed` from a confirmed PEP decision.
- `tests/wfp/test_t11_wfp_enforcement.py` still asserts "Rust PEP remains the
  sole authority for privileged host effects" — the opposite of the decision.
- `docs/adr/0001` still lists `Rust PEP | shield/src/lib.rs | Final enforcement
  authority`.

Why it was not patched in this session: it is a coordinated cross-language
contract retirement (C driver, bridge, Rust FFI, Zig control, evidence
projection, tests, ADR, maps). Editing one layer and not the rest would itself
be a stop-the-line. The repo rule is explicit: the shared contract and every
codec/consumer change in the same patch.

Smallest safe next slice (proposed, source-only, no ABI deletion):
1. Driver: make `IOCTL_AEGIS_BLOCK_FLOW` return `STATUS_NOT_SUPPORTED` before
   any state change; keep `UNBLOCK` as cleanup-only for pre-existing
   AEGIS-owned filters. Rebuild with `scripts/wdk_build_production.ps1`.
2. Rust: `aegis_pep_enforce` classifies evidence and returns the assessment
   outcome; it must not load or call the adapter, and BLOCK/QUARANTINE become a
   non-effect decision. Keep the symbol for ABI compatibility.
3. Zig control: hard-refuse `enforcement.block/quarantine` with
   `DETECTION_ONLY` before any gate check; keep `unblock` cleanup-only.
4. Zig pipeline: `confirmed` is structurally false; projection always
   `observed`, `host_effect_confirmed=false`.
5. Rewrite T11 to the IDS contract plus negative tests proving no block filter
   can be installed/requested and no receipt claims a host effect.
6. Update ADR-0001 and all maps, then rebuild truth.

Acceptance can only reach E1 (driver source + build) + E2 (Rust/Zig/tests).
Driver load and AEGIS filter absence on the host remain E5 and require a
test-signed driver swap under elevation.

### #28 — Ingestion payload/provenance contract

Requires a new versioned frame binding bounded payload + provenance to the
frozen CanonicalEvent v1/v2, plus all six codecs and the shared `event_v*`
vector in one patch, plus Go-side verdict removal in the same transaction.
Not a single-layer edit by design. Blocked on that coordinated change, not on
tooling.

### #29 — Minifilter rows dropped at pipeline ingress

Real measured loss (`queue dropped 52,823` on the live host, ETW-attributed;
`by_source_kind` now provides the per-source-per-kind instrument). The
reduction decision (bounded admission vs throughput) must follow attributable
burst measurements from a build that contains `2e715df`. Blocked on a deployed
current build, not on source work. Coalescing stays blocked by the FIM
producer-identity stop-line (ADR-0012, NOT PASSED).

### #30 — 0xc0000374 heap corruption / SCM restart

Needs Page Heap plus repeated service start/stop cycles under elevation to
attribute the crash. Source-side hardening already landed (`FIM-STOP-002`), but
the crash root cause is not proven. Blocked on host instrumentation.

## What this machine can and cannot prove

- Can prove now: Zig/Rust/Python suites, builds, truth/evidence consistency,
  artifact hashes, static authority contracts.
- Cannot prove without privileged host work: driver load/absence of block
  filters, current-source E5 for XDR receipt/replay, burst loss reduction,
  heap-crash root cause.
- Cannot prove without owner-held key material: E7 signed release; production
  driver signing (ring is test-signed).

## Honest completion statement

The detection-only backend is source-complete and test-green at E2 for the
modules it covers. The project is **not** release-ready: #25 and #28 are open
source contradictions, #29 and #30 are open host defects, current-source
deployment is not done, and no signed release exists. Closing any of them
requires either a coordinated multi-layer patch (#25/#28) or an elevated host
window (#29/#30/E5/E7).
