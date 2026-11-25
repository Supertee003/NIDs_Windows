# Verification summary — read in 3–5 minutes

> **These are recorded results, not a fresh run performed while writing this page.**
> Each row carries its evidence location and the commit it belongs to. Do not merge
> numbers from different commits into one "current run". No PASS is entered without
> a recorded artifact. Human-readable detail: [`docs/testing/RESULTS.md`](../testing/RESULTS.md).
> Status source: [`release/release-status.json`](../../release/release-status.json).

## Tested commit / environment

| Item | Value |
|---|---|
| Current records HEAD | Moves with each records patch (check `git rev-parse HEAD`) |
| Current build source | `43a8bcc02358076380fa938b0e5632870643d3c5` |
| Release identity (immutable) | `v1.1` / signed candidate `466a226` / build source `a53eda8` |
| Host family | 64-bit Windows 10/11; isolated lab or disposable VM for host tests |
| Toolchain | Zig 0.13.0, Rust 1.75+, Go 1.22+, Python 3.11+, CMake 3.27+, VS2022 MSVC, Windows SDK/WDK |

## Result table

| Category | Recorded result | Evidence | Commit / build source |
|---|---|---|---|
| Build | RECORDED PASS (`zig build rc=0`) in release records; no fresh build claimed here | `docs/testing/RESULTS.md`; `EVIDENCE_INDEX.json` | `a53eda8` release record; current maps `43a8bcc` |
| Unit | RECORDED: Python **1,471 passed / 0 skipped** (sum of two phases, not one invocation). Zig snapshots: **2116 / 2114 / 2109 passed** with 10–11 skips — never claim zero skips for Zig | `docs/testing/RESULTS.md:9-37` | `a53eda8` (Python); distinct historical Zig entries |
| Integration | RECORDED PASS: E3 private-pipe exact deltas at current source | `analysis/current-head/MASTER-AUDIT-P8-I44-SOURCE-43A8BCC-E3-20261125.md` | `43a8bcc` |
| Protocol | RECORDED: exact-length / trailing-byte / version-downgrade rejection tests in Zig, Go, C++; shared `event_v*` vectors | `src/contract/canonical_event.zig:1624-1635`; `nose/payload_v3_test.go:288-289`; `docs/protocol/INDEX.md` | `43a8bcc` |
| Runtime | RECORDED: counted drops/shed, worker failure reason, DEGRADED health tests; no fresh probe by this summary | `docs/runtime/HEALTH_MODEL.md`; `src/control/state_machine.zig:651-717` | `43a8bcc` |
| Live host | RECORDED PASS at **narrow scope**: owner-run elevated canonical-pipe `-inject` with verified stop/restore. Full current-head Windows E5 / kernel qualification: **NOT_PROVEN** | `analysis/current-head/MASTER-AUDIT-P8-I44-SOURCE-43A8BCC-E4E5-20261125.md`; `runtime_manifest.json:535` | `43a8bcc` |
| Detection | 23/23 catalogued and evaluable **at fixture/code-path level**; 22/23 host-evaluable; live positive proof is L4 family only (R9006 strongest). R2003 has no host proof (FN-1) | `docs/portfolio/DETECTION_CATALOG.md`; `README.md:57-71`; `docs/testing/RESULTS.md:60-72` | catalog current; E5 proofs historical at their own commits |
| Soak | RECORDED PASS **36.52 / 24.0 h**, `problems=[]`, zero loss/shed counters **only in that recorded window**; HISTORICAL at release identity | `analysis/current-head/SOAK-PASS-466A226-20261122.md`; `docs/testing/RESULTS.md:39-58` | `a53eda8` |

## What the numbers do not prove

- 674/674 means artifact hashes verified against **one** Ed25519 signature over
  `SHA256SUMS`; it is not 674 signatures and not security validation of each artifact.
- A synthetic fixture is E1/E2; it does not prove a real sensor produced the event.
- The narrow `43a8bcc` E4/E5 proof does not establish detection matrix, soak, loss-rate,
  install, signing, E6/E7 or full host qualification.
- `a26c573` and `03bb86d` proofs are HISTORICAL and do not substitute for current-source proof.

## Known limitations

See [`README.md` § Known limitations](../../README.md#known-limitations--read-before-the-proof-numbers)
and the full list at [`README.md` § Known limitations and open work](../../README.md#known-limitations-and-open-work).
Highest-priority gaps: R2003 command-line producer, VLAN/IPv6 coverage, collector
shutdown, active IPC nonce/replay, cross-language ABI byte vector, and owner-side
signing / attestation.
