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
| Current build source | `4dd33936909de1314099652a7523e52c40bb2c44` (S4 canonical policy bytes; S1 `493648f`, S2 `4bc8244`, S3 `f1f89c1`). C6 `7822f4c` and prior records are HISTORICAL at this source. |
| Release identity (immutable) | `v1.1` / signed candidate `466a226` / build source `a53eda8` |
| Host family | 64-bit Windows 10/11; isolated lab or disposable VM for host tests |
| Toolchain | Zig 0.13.0, Rust 1.75+, Go 1.22+, Python 3.11+, CMake 3.27+, VS2022 MSVC, Windows SDK/WDK |

## Result table

| Category | Recorded result | Evidence | Commit / build source |
|---|---|---|---|
| Build | FRESH E2 at C6: `go test ./...` PASS and `zig build test --summary all` 8/8 steps, 2142 passed / 10 skipped (helper stubs staged from `build/`; no new release build claimed) | `analysis/current-head/MASTER-AUDIT-C6-CAPTURE-20261125.md` | `7822f4c` |
| Unit | RECORDED: Python **1,471 passed / 0 skipped** (sum of two phases, not one invocation). Zig snapshots: **2116 / 2114 / 2109 passed** with 10–11 skips — never claim zero skips for Zig | `docs/testing/RESULTS.md:9-37` | `a53eda8` (Python); distinct historical Zig entries |
| Integration | **FRESH E3 PASS at current source**: narrow private-pipe `-inject` exact deltas, harness SHA256 `3CAB8A36…C67` (narrow E4/E5 proven separately on the elevated canonical pipe) | `analysis/current-head/MASTER-AUDIT-C6-E3-CURRENT-SOURCE-20261125.md`; `analysis/current-head/MASTER-AUDIT-C6-E4E5-CURRENT-SOURCE-20261125.md` | `7822f4c` |
| Protocol | RECORDED: exact-length / trailing-byte / version-downgrade rejection tests in Zig, Go, C++; shared `event_v*` vectors | `src/contract/canonical_event.zig:1624-1635`; `nose/payload_v3_test.go:288-289`; `docs/protocol/INDEX.md` | `43a8bcc` |
| Runtime | RECORDED: counted drops/shed, worker failure reason, DEGRADED health tests; no fresh probe by this summary | `docs/runtime/HEALTH_MODEL.md`; `src/control/state_machine.zig:651-717` | `43a8bcc` |
| Live host | Narrow E4/E5 PASS: owner-run elevated canonical-pipe `-inject`, exact deltas, verified stop/restore. Full current-head Windows E5 / kernel qualification: **NOT_PROVEN**; the narrow proof predates S1–S4 and is HISTORICAL at `4dd3393` | `analysis/current-head/MASTER-AUDIT-C6-E4E5-CURRENT-SOURCE-20261125.md`; `runtime_manifest.json:535` | `7822f4c` (HISTORICAL at `4dd3393`) |
| Detection | 23/23 catalogued and evaluable **at fixture/code-path level**; 22/23 host-evaluable; live positive proof is L4 family only (R9006 strongest). R2003 has no host proof (FN-1) | `docs/portfolio/DETECTION_CATALOG.md`; `README.md:57-71`; `docs/testing/RESULTS.md:60-72` | catalog current; E5 proofs historical at their own commits |
| Soak | RECORDED PASS **36.52 / 24.0 h**, `problems=[]`, zero loss/shed counters **only in that recorded window**; HISTORICAL at release identity and at `4dd3393` | `analysis/current-head/SOAK-PASS-466A226-20261122.md`; `docs/testing/RESULTS.md:39-58` | `a53eda8` |
| Fuzz (new) | REAL E2 deterministic smoke: seed `0xDEADBEEF`, 1,000 inputs, leak guard clean, binary SHA-256 `7681B52F…C621`; coverage-guided campaign still NOT_RUN | `docs/testing/FAULT_INJECTION_INVENTORY.md` §1a | `4dd3393` |
| Microbenchmark (new) | REAL E2 ReleaseFast `quick` 6/6 thresholds PASS, `latency` p50/p95/p99 recorded; binary SHA-256 `8829E03D…DA476`; fixed-rate network benchmark still NOT_RUN | `docs/portfolio/PERFORMANCE_REPORT.md` §1a | `4dd3393` |
| CI (new) | REAL E4 hosted CI green: push run `45675880854` and dispatch `45676093328`, both `success` at records HEAD `e64ea25`; all jobs + `ci-matrix` PASS. Not E5/E6/E7 | `docs/CI_QUALITY_GATES.md` §4a | `4dd3393` |
| Full local suite (new) | `pytest -m "not host_live" -q` → **1,518 passed, 1 skipped, 18 deselected, 27 subtests** | `analysis/current-head/MASTER-AUDIT-AEGIS-PLAN-007-020-20261126.md` follow-up | `4dd3393` |

## What the numbers do not prove

- 674/674 means artifact hashes verified against **one** Ed25519 signature over
  `SHA256SUMS`; it is not 674 signatures and not security validation of each artifact.
- A synthetic fixture is E1/E2; it does not prove a real sensor produced the event.
- The narrow `43a8bcc` E4/E5 proof is HISTORICAL at that source; it does not establish detection
  matrix, soak, loss-rate, install, signing, E6/E7 or full host qualification at `7822f4c`.
- C6 source-level visibility/shutdown changes remain E2 only; the current-source E3/E4/E5 proof covers the pipe-reader exact deltas and host lifecycle, not the capture path or detection efficacy. Full Windows E5/kernel qualification is not proven.
- `a26c573`, `03bb86d` and `43a8bcc` proofs are HISTORICAL and do not substitute for current-source proof.

## Known limitations

See [`README.md` § Known limitations](../../README.md#known-limitations--read-before-the-proof-numbers)
and the full list at [`README.md` § Known limitations and open work](../../README.md#known-limitations-and-open-work).
Highest-priority gaps: R2003 command-line producer, VLAN/IPv6 coverage, collector
shutdown, active IPC nonce/replay, cross-language ABI byte vector, and owner-side
signing / attestation.
