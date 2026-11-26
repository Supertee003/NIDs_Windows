# Remaining gaps disposition — build source `aa3b7b0` — 2026-11-26

**RECORD-ID:** `REMAINING-GAPS-DISPOSITION-AA3B7B0-20261126`
**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5`
**RECORDS HEAD:** moves with this records-only patch; the build source does not move (ADR-0008).

## Purpose and rules

This page closes the **documentation side** of the remaining gap list after the
gaps-first direction that voided soak `20261126-214622`. It uses two deliberately
different dispositions:

1. **`PHYSICAL PROOF AT CURRENT SOURCE`** — a real, recorded observation at
   `aa3b7b0`; it carries an evidence level and a result.
2. **`CLOSED as documented gap`** — the status page now states the gap, its
   boundary and why no physical proof exists. **This is a documentation status
   only.** It does not promote any evidence `status`, `level`, `result` or
   `status_basis`, and it does not change any gate verdict. The underlying
   evidence stays `NOT_RUN` / `NOT_PROVEN` / `E2` exactly as recorded.

`OPEN` is still used for work that has a real path to a current-source verdict.
The only such item is `soak_24h`.

## 1. Gaps closed with physical proof at `aa3b7b0`

| Gap | Disposition | Evidence |
|---|---|---|
| Canonical pipe-reader bounded shutdown + exact framing/loss deltas | **PHYSICAL PROOF AT CURRENT SOURCE — E5 narrow PASS** | `PIPE-READER-SHUTDOWN-E5-AA3B7B0-20261126.md`; harness compiled from current source, SHA-256 `55306B0A…710B3`, `frames_read=1 submitted=1 rejected=0 dropped=3 pipe_errors=2`, verified restore |
| R2003 `CommandLine` producer host re-measurement | **PHYSICAL PROOF AT CURRENT SOURCE — E5 narrow PASS** | `R2003-CMDLINE-HOST-PROOF-E5-AA3B7B0-20261126.md`; one verified `rule_id=2485705370` row, two independent negative controls, verified restore. The earlier contaminated-marked `v1` attempt is retained as `NOT_PROVEN` |

Both were elevated owner runs that swapped current-source binaries and restored
hash-identical baselines. Neither is a matrix, soak, driver, E6 or E7 proof.

## 2. Gaps closed as documented gaps (no physical proof claimed)

| Gap | Evidence status (unchanged) | Documentation disposition | Why no physical proof at `aa3b7b0` |
|---|---|---|---|
| Coverage-guided fuzz campaign | `NOT_RUN` | **CLOSED as documented gap** | No coverage-guided engine is installed (no clang/libFuzzer, AFL++, honggfuzz, cargo-fuzz/nightly or Atheris; Zig 0.13 has no `zig fuzz`). The real E2 deterministic 1,000-case smoke and microbenchmarks remain `docs/portfolio/CURRENT_HEAD_FUZZ_BENCH-20261126.md` |
| Full 23-rule matrix E5 | `NOT_PROVEN` | **CLOSED as documented gap** | The matrix was last measured at `f4cde3c`; `43a8bcc` / `7822f4c` rows are HISTORICAL. Current source has R9006 narrow E6 and R2003 narrow E5 only; there is no stimulus set for the other rules |
| VLAN / QinQ and IPv6 extension-header host visibility | `NOT_PROVEN` (E2 pins only) | **CLOSED as documented gap** | No tagged-frame injector exists; the available host selector is DLT_NULL loopback. Source fixes and Zig pins are E1/E2, not a host observation |
| Go `capture.go` adapter shutdown on a real Ethernet adapter | E2 only | **CLOSED as documented gap** | The elevated proof covers the canonical pipe reader, not the Go capture goroutine on a physical NIC. The `capture.go` monitor-shutdown E2 pins remain E2 |
| Signed driver, load/unload/cleanup at current source, full Windows E5 / kernel IDS qualification | `NOT_PROVEN` | **CLOSED as documented gap** | Both `.sys` files remain `NotSigned`; no HLK/production-signing decision and no current-source lifecycle transcript. Historical installer records are not substitutable. See `docs/runtime/KERNEL_LIFECYCLE.md` |
| E7 release verification | `NOT_RUN` / `NOT_PROVEN` | **CLOSED as documented gap** | E7 means release signing/rebuild; published identity `v1.1` / `466a226` / `a53eda8` is immutable and the `6c94b47` record is additive. A soak PASS would not itself create E7 |
| Clean install / uninstall campaign at current source | `NOT_RUN` | **CLOSED as documented gap** | Requires a disposable-host installer campaign with current hashes; no such campaign was executed at `aa3b7b0` |

Closing these as documented gaps means the status pages stop implying an
unresolved *investigation* is still open. It does **not** mean the capabilities
were proven. Any future owner run that produces real evidence must create a new
evidence entry at its actual source; this page is not credit for it.

## 3. Still OPEN

| Item | Status | Next step |
|---|---|---|
| `soak_24h` at `aa3b7b0` | **OPEN** — no fresh 24 h verdict; three attempts voided (`162907`, `172958`, `214622`), none credited | Run a fresh SYSTEM-finalized window with no other host work, recycle `AegisMinifilter` before the window, accept only `verdict=PASS`, `elapsed_hours>=24`, `problems=[]`, `restore.verified=true` |

## 4. Gate and evidence invariants

- Gate board remains **5/6 PASS, `soak_24h` OPEN — NOT SHIPPABLE**.
- No evidence `status`, `level`, `result` or `status_basis` was rewritten by this
  disposition; the two new host proofs are **new** evidence entries.
- No test was skipped, xfailed, relaxed or edited to hide a failure.
- No `PASS` was fabricated for `NOT_RUN` / `NOT_PROVEN` work.
