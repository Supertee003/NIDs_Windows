# ADR-0014 — Q-LOSS ingress isolation: filter the ETW `NameDelete` lane, never silently

**Status:** **PROPOSED — owner decision required.** No code is written against
this ADR. The three options below change different things (which rows exist,
how fast they are written, or what the release promises), so the choice is a
product decision, not an implementation detail.
**Date:** 2026-11-17
**Measurement:** `QLOSS-CRITICAL-001-E5-20261107`, `QLOSS-CONSUMER-001-E5-20261107`,
`QLOSS-FAIRSHARE-001-E5-20261107`, ADR-0012 census (2026-11-17)
**Amends open work item 1 of:** ADR-0010 (Host telemetry admission under storm)
**Related:** FLOW `QLOSS-HEALTH-001`, GitHub issue #29, gap
`GAP-QLOSS-ISOLATION-002`, ADR-0012 (FIM lane — coalescer rejected at E5)

---

## Context

The known-gap record says: *FIM/ETW ingress volume from the storming source is
not reduced.* Fair-share arithmetic was already fixed at E2 (`QLOSS-FAIRSHARE-001`),
so one storming sensor can no longer blind another; what remains is a sensor
producing more rows than the host consumer can drain, which no admission policy
can remove.

Measured facts, all from deployed E5 windows on this host:

| Fact | Value | Source |
|---|---|---|
| Consumer capacity (ReleaseSafe, 60k-file churn) | 2,930 rows/s, 439 drops (0.12%) | `QLOSS-CONSUMER-001-E5-20261107` |
| ETW demand in the 20k-churn window | 245,343 pushed + 42,456 dropped (287,799, ~1,599/s) | `QLOSS-CRITICAL-001-E5-20261107` |
| Combined FIM+ETW demand, same window | ~869,409 rows (~4,830/s) vs 2,930/s capacity | same |
| Largest single ingress lane | ETW Kernel-File `NameDelete`: **18,151,604 rows** | ADR-0012 census |
| FIM coalescing as a lever | **rejected** at E5 — the lane does not duplicate | ADR-0012, `ADR-0012-SINGLE-HOST-E5-20261117` |

Two facts bound the design space:

1. **The lane is not duplicate delivery.** ADR-0012 proved a create-once,
   one-open-per-path churn produces one record per open. Any volume reduction
   here is therefore a *semantic* decision — which deletes deserve a row — and
   must be visible, counted, and reversible. `AGENTS.md` forbids silent event
   loss.
2. **Deletes are not inert.** The kernel-file rules match path text, so a delete
   of `C:\Windows\System32\x.dll` matches `R1001`/`R1004` today, and a
   mass-delete of `*.locked` files is exactly the ransomware signal `R1002`
   exists for. A filter must not remove rows that would have carried a rule id.

## Options

### A. Producer-side filter: drop only deletes that match no rule path, aggregate the rest

At the ETW consumer, a `NameDelete` whose path matches **no** kernel-file
pattern is not enqueued as its own event. Matching deletes keep flowing
unchanged. The dropped volume is reported as a per-window aggregate plus a
visible counter (`etw_delete_filtered_total`, `etw_delete_aggregate_events`), and
the aggregate row carries the window's delete count, the top-N path prefixes and
one sample path — so a mass delete still appears as one high-count event instead
of millions of rows.

- Removes ~18.1 M of the largest lane while leaving the *match set* identical.
- Every removed row was one that carried `rule_id = 0`; nothing that could have
  raised a rule disappears.
- Cost: producer change in C++ (ETW adapter) + Zig consumer counter + tests
  (~2 days), then a new build, signature and 24 h soak.
- Risk: a future rule that keys on volume of *unmatched* deletes would need the
  aggregate, not the raw lane. The aggregate exists for that reason.

### B. Batched forensic append (consumer throughput)

Keep every row, reduce the per-row cost: the append currently pays a 4 KiB
zero/hash/CRC pass per record; batching amortises it.

- Semantics-neutral, which makes it the safest change to detection.
- Does not bound the burst amplitude, only raises the ceiling by an unknown
  amount until measured.
- Cost: forensic writer change + a new measurement run (~2–3 days) + soak.
- Companion, not a substitute: A and B address different halves of the same
  equation.

### C. Accepted envelope (documented budget + owner sign-off)

Ship with the current lane, publish the loss envelope, and record an explicit
owner acceptance for `source_quota_shed`/`reserved_tail_shed` during storms.

- Zero code, zero new soak; cheapest by far.
- Leaves the gap open by definition: the platform still produces rows it cannot
  drain, and the acceptance has to be restated for every release.
- Requires a named owner sign-off; this ADR cannot supply it.

## Recommendation

**A, with B as a follow-up in the same v1.1 batch if the measurement shows B is
still needed after A lands.** Reasons:

- A is the only option that reduces volume *without* touching what detection can
  see: the row set that carries a rule id is unchanged by construction, and the
  removed rows are exactly the ones already recorded as `rule_id = 0`.
- It keeps ransomware visibility through the aggregate, so the security property
  that justified the lane is preserved rather than traded away.
- It is bounded and cheap to verify: post-change, `etw_delete_filtered_total > 0`,
  kernel-file match count unchanged for the same stimulus, `shed_overload` under
  the 4,000 budget, ring drops 0.
- C is not rejected on merit but on repeatability: it re-opens every release.

## Acceptance criteria (for whichever option is chosen)

1. Same stimulus, same window length: total queue drops and `shed_overload`
   strictly below the `QLOSS-CRITICAL-001` baseline.
2. Kernel-file detection unchanged: a `canary.locked` rename/delete still yields
   `R1002`; `R1001`/`R1004` still fire for matching paths.
3. Any suppressed row is counted in a counter that appears in `status`/`metrics`,
   and the aggregate is emitted for mass deletes.
4. A 24 h soak on the new build with the same budgets (`--loss-budget 3500`,
   `--shed-budget 20000`) passes with no restart.

## Consequences

- If A is chosen, the forensic record for a delete storm becomes one aggregate
  row plus the matching deletes, not millions of rows; the raw lane is no longer
  replayable for unmatched deletes. That is a real loss of forensic granularity
  and is the price of the change — it must be stated in the release notes.
- Either way the work lands in the single v1.1 batch with the 6.0.0 label, so it
  costs one build, one signature and one soak instead of two.
- The gap stays **open** until the chosen option is implemented, measured, and
  soaked. This document does not close it.

## Measurement of option B on this host (2026-11-18)

Option B claims that batching the forensic append "amortises" the per-record
4 KiB pass. Measured with the ring's own code (`src/forensic/crc32_slicing.zig`,
`std.crypto.hash.sha2.Sha256`), 20,000 iterations, `-OReleaseSafe`, on the host
the product runs on:

| part of the mandatory pass | per record |
|---|---|
| `@memset(slot, 0)` over 4 KiB | **50 ns** |
| SHA-256 over the same 4,092-byte span the chain covers | **2,387 ns** |
| CRC32 slicing-by-8 over the same span | **1,792 ns** |
| **total mandatory pass** | **≈ 4.2 µs** |
| SHA-256 over a 200-byte header+payload span (for comparison) | **176 ns** |

The observed `stage=forensic_append p50` on the live daemon is 16.4 µs, so the
mandatory pass is roughly a quarter of the append and the rest is record
construction, the ring mutex and perf instrumentation.

**Conclusion: B as specified cannot deliver what it promises.** The hash chain is
per-record and serial (record N hashes `prev_hash` of record N-1), so records
cannot be hashed in parallel or in one batch, and the hash covers the *whole*
slot by contract. Batching therefore amortises only the memset and the lock --
about 50 ns out of 4,200 ns, i.e. ~1%. The ~14x win that would matter
(4.2 µs → 0.3 µs) comes from *narrowing the hashed span* to header + payload,
which is a **format and integrity-contract change**, not a batching change: it
needs its own ADR, a coverage-version byte so old and new records can be
distinguished, matching changes in `verifyRecord`, `verifyHashChain`,
`replay_verifier` and the handler's verify path, plus golden-vector updates.

Recorded, not implemented: changing what the forensic hash covers silently is a
crypto-contract change and is out of scope for this ADR.
