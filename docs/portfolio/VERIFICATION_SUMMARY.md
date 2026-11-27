# Verification summary — read in 3–5 minutes

> **These are recorded results, not a fresh run performed while writing this page.**
> Each row carries its evidence location and the commit it belongs to. Do not merge
> numbers from different commits into one "current run". No PASS is entered without
> a recorded artifact. Human-readable detail: [`docs/testing/RESULTS.md`](../testing/RESULTS.md).
> Status source: [`release/release-status.json`](../../release/release-status.json).  
> Scope source: [`docs/SCOPE.md`](../SCOPE.md) — detection-only / observe-only; no IPS or production host enforcement claim.

## Tested commit / environment

| Item | Value |
|---|---|
| Current records HEAD | Moves with each records patch (check `git rev-parse HEAD`) |
| Current build source | `aa3b7b0161e425e54155d5767737bffcde7939b5` (loopback BPF fix). Predecessor `4dd3393` carried S4 canonical policy bytes; S1 `493648f`, S2 `4bc8244`, S3 `f1f89c1`. `4dd3393`, C6 `7822f4c` and prior records are HISTORICAL at this source. |
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
| Pipe-reader shutdown (current) | **E5 narrow PASS**: current-source harness (SHA-256 `55306B0A…710B3`), three failing shapes + one valid frame, `frames_read=1 submitted=1 rejected=0 dropped=3 pipe_errors=2`, verified restore | `analysis/current-head/PIPE-READER-SHUTDOWN-E5-AA3B7B0-20261126.md`; raw `shutdown-e5/` | `aa3b7b0` |
| R2003 producer (current) | **E5 narrow PASS**: one verified `rule_id=2485705370` row from an IEX command line, two independent negative controls, verified restore; earlier contaminated-marker attempt retained `NOT_PROVEN` | `analysis/current-head/R2003-CMDLINE-HOST-PROOF-E5-AA3B7B0-20261126.md`; raw `r2003-e5/` | `aa3b7b0` |
| Detection | 23/23 catalogued and evaluable **at fixture/code-path level**; recorded census 22/23 host-evaluable; live positive proof is L4 family (R9006) plus R2003 **narrow E5 at `aa3b7b0`**; full matrix still not re-measured | `docs/portfolio/DETECTION_CATALOG.md`; `README.md:57-71`; `R2003-CMDLINE-HOST-PROOF-E5-AA3B7B0-20261126.md` | catalog current; full-matrix E5 proofs historical at their own commits |
| Soak | RECORDED PASS **36.52 / 24.0 h**, `problems=[]`, zero loss/shed counters **only in that recorded window**; HISTORICAL at release identity and at `4dd3393` | `analysis/current-head/SOAK-PASS-466A226-20261122.md`; `docs/testing/RESULTS.md:39-58` | `a53eda8` |
| Fuzz (current) | REAL E2 deterministic smoke at current source: 1,000 cases, thresholds PASS; coverage-guided campaign still **NOT_RUN** | `analysis/current-head/CURRENT_HEAD_FUZZ_BENCH-20261126.md` | `aa3b7b0` |
| Microbenchmark (current) | REAL E2 ReleaseFast `quick` thresholds PASS with recorded `latency` percentiles at current source; fixed-rate **network** benchmark now PASS narrow E5 at 100 connections/s for 60 s | `analysis/current-head/CURRENT_HEAD_FUZZ_BENCH-20261126.md` (raw `netbench/`) | `aa3b7b0` |
| CI (new) | REAL E4 hosted CI green: push run `45675880854` and dispatch `45676093328`, both `success` at records HEAD `e64ea25`; all jobs + `ci-matrix` PASS. Not E5/E6/E7 | `docs/CI_QUALITY_GATES.md` §4a | `4dd3393` |
| Full local suite (new) | `pytest -m "not host_live" -q` → **1,518 passed, 1 skipped, 18 deselected, 27 subtests** | `analysis/current-head/MASTER-AUDIT-AEGIS-PLAN-007-020-20261126.md` follow-up | `4dd3393` (HISTORICAL at `aa3b7b0`) |
| Full local suite (current) | `pytest -m "not host_live" -q` → **1,520 passed, 1 skipped, 18 deselected, 27 subtests**; `go test ./...` PASS; docs/release 278 passed | this worktree, recorded in `analysis/current-head/MASTER-AUDIT-LOOPBACK-BPF-E6-AA3B7B0-20261126.md` §5 | `aa3b7b0` |
| Host_live loopback (new) | **E6 PASS, narrow**: both loopback scan tests pass at the current source with 2 attributable R9006 rows and verified elevated restore; not a 23-rule matrix, soak, driver or E7 proof | `analysis/current-head/MASTER-AUDIT-LOOPBACK-BPF-E6-AA3B7B0-20261126.md`; `docs/testing/HOST_LIVE_DIAGNOSIS.md` §6 | `aa3b7b0` |
| Release record (current) | **PASS E2**: additive Ed25519 record `release/T20-final/6c94b47` verifies under owner anchor `DCNPphsq…`; release-record verification only, not E5/E6/E7 | `analysis/current-head/RELEASE-SIGNATURE-AA3B7B0-20261126.md`; `docs/gates/RELEASE_TRUST_ANCHOR.md` | `aa3b7b0` |
| Release board (current) | **5/6 PASS with `soak_24h` OPEN — NOT SHIPPABLE**; two soak windows voided, no fresh 24 h verdict | `analysis/current-head/CURRENT-HEAD-CLOSEOUT-AA3B7B0-20261126.md`; `docs/gates/T20_100pct_audit.md` | `aa3b7b0` |

## What the numbers do not prove

- 674/674 means artifact hashes verified against **one** Ed25519 signature over
  `SHA256SUMS`; it is not 674 signatures and not security validation of each artifact.
- A synthetic fixture is E1/E2; it does not prove a real sensor produced the event.
- The narrow `43a8bcc` E4/E5 proof is HISTORICAL at that source; it does not establish detection
  matrix, soak, loss-rate, install, signing, E6/E7 or full host qualification at `7822f4c`.
- C6 source-level VLAN/IPv6 visibility and the **Go `capture.go` adapter** shutdown remain E2 only; the current-source E5 proof covers the canonical pipe reader and the R2003 producer, not the physical-NIC capture path or the full detection matrix. Full Windows E5/kernel qualification is not proven.
- `a26c573`, `03bb86d`, `43a8bcc` and `4dd3393` proofs are HISTORICAL and do not substitute for current-source proof.
- The current-source S2/S3 and loopback results are narrow E5/E6 proofs; they do not establish the
  full 23-rule matrix, a 24 h soak, driver/kernel lifecycle, or E7 release qualification.

## Known limitations

See [`README.md` § Known limitations](../../README.md#known-limitations--read-before-the-proof-numbers)
and the full list at [`README.md` § Known limitations and open work](../../README.md#known-limitations-and-open-work).
The only OPEN item is a fresh 24 h soak at `aa3b7b0`. Full 23-rule matrix E5, coverage-guided
fuzzing, driver/kernel lifecycle proof, E7 qualification, clean install/uninstall and VLAN/IPv6
host visibility stay `NOT_RUN`/`NOT_PROVEN` and are `CLOSED as documented gap` — see
`analysis/current-head/REMAINING-GAPS-DISPOSITION-AA3B7B0-20261126.md`; no gate, level, result or
`status_basis` was promoted. Narrow current-source E5 proofs exist for active IPC nonce/replay,
durable identity, the canonical pipe reader and the R2003 producer; the Go capture adapter and
cross-language ABI byte vectors remain source-closed at E2.
