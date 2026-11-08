## STOP-THE-LINE: uncommitted forensic batch append is incomplete

Current checkout at records HEAD `cb28a7c6cb59eedcff40fd265599c545d431c5f8` has an uncommitted change in `src/forensic/forensic_pipeline.zig` adding `ForensicRing.appendBatch`.

Read-only source inspection shows the candidate method does not match its own intended slice contract: its `events` parameter is declared as a pointer to one `IpcEvent` but is used with `.len` and indexing; array companions are pointer-to-slice types but similarly used as direct slices; `std.debug assert` is not Zig assertion syntax. The implementation also breaks out on null payload or ring wrap and commits the partial batch without a result describing rejected/unwritten records, while not updating overwrite accounting. A hash chain and append semantics must not silently accept partial batches.

This issue records the stop-line finding only. Preserve the author's current diff. Do not build/test while the daemon is running. Before implementation, define the batch API contract (owned slices/length, null semantics, all-or-nothing vs explicit partial result, wrap behavior, overwritten counter semantics, hash/CRC equivalence to append) and add tests at that contract seam. Then implement atomically and rebase truth/evidence.

Current truth check fails `<source-worktree>` because this source file is modified. Existing maps are not current truth until this diff is completed or reverted and truth is regenerated.

## Resolution update (2026-11-08)

FOR-BATCH-001 is implemented and committed at source commit `cf19e13`.

- The batch API takes `[]const AppendRecord`; payloads are variable-length borrowed slices, and every record goes through the exact same `appendLocked` writer while one mutex is held.
- Direction is validated for the entire batch before mutation. Invalid direction returns `error.InvalidDirection` with no writes; empty input leaves the chain unchanged. `initMemory` rejects undersized or non-record-aligned capacities.
- A byte-equivalence test initially failed and exposed uninitialized implicit padding in `RecordHeader`; `writeSlot` now zeros all ABI padding before hash/CRC. Record layout is unchanged.
- Verification: focused forensic suite 20/20; full `zig build test --summary all` 2058 passed, 10 skipped, 0 failed; `zig build` passed; `git diff --check` passed. Service was confirmed STOPPED.
- Detailed patch/evidence record: `analysis/current-head/FOR-BATCH-001-20261108.md`.

Issue #31 may close for this source-level/E2 completion gate after maps/evidence rebaseline. This does not close other forensic backlog or Windows E5/release blockers.
