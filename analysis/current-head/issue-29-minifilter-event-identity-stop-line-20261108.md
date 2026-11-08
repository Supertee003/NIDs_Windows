# STOP-THE-LINE — QLOSS-COALESCE minifilter event identity

**Date:** 2026-11-08  
**Related issue:** #29 (telemetry loss)  
**Trigger:** Potential forensic inconsistency under `AGENTS.md` STOP-THE-LINE triggers  
**Status:** OPEN — do not deploy or merge the current coalescing WIP

## Finding

The current uncommitted `QLOSS-COALESCE` implementation identifies a
minifilter duplicate by `(path, event kind, process id)` and passes timestamp
`0` to the coalescer. The driver contract shows that this is not sufficient to
identify a duplicate callback:

- `drivers/minifilter/aegis_minifilter.c` registers `AegisPostOperation` for
  `IRP_MJ_CREATE`.
- `drivers/minifilter/aegis_minifilter_file.c::AegisPostOperation` writes a
  ring record for every successful create/open callback.
- `drivers/minifilter/aegis_minifilter_comm.c::AegisRingWriteEvent` stamps each
  record with a fresh `KeQuerySystemTime` value.

Therefore two legitimate opens of the same path by the same process within a
single pull can share `(path, kind, pid)` while representing different events.
The current WIP would suppress the later event and lose forensic activity.
The earlier E5 duplicate-ratio measurement used the same coarse identity; it
does not prove those repeats are duplicate deliveries. Its same-timestamp count
is a useful candidate signal, not yet a verified event identity contract.

## Required resolution before implementation resumes

1. Define minifilter identity from the actual producer contract. A monotonic
   record sequence assigned by the driver is a stronger candidate than the
   current timestamp; `(path, kind, pid, timestamp)` is only acceptable if
   evidence proves the timestamp uniquely distinguishes every legitimate
   callback in the bounded batch.
2. Confirm timestamp resolution and whether duplicate ring delivery preserves
   the original timestamp. `KeQuerySystemTime` may return the same value for
   distinct callbacks close together, so timestamp equality alone must not be
   assumed to prove duplicate delivery. If no stable identity exists, do not
   suppress minifilter rows; pursue queue capacity/consumer throughput or
   another lossless mechanism instead.
3. Re-measure the coalescible ratio using the corrected key before claiming the
   accepted throughput threshold is met.
4. Add a contract test proving two same-path, same-kind, same-PID records with
   distinct timestamps are both retained, and exact repeats are counted.
5. Keep `fim_coalesced_total` and fail-open overflow accounting; rerun E5 only
   after the identity gate passes.

## Current WIP and verification

The code changes remain uncommitted. The local `zig build`, `zig build test`,
and 8 focused coalescer tests passed, but these establish compilation and the
coarse-key behavior only; they do not qualify the event identity. Do not install
or deploy the resulting workspace binary. The installed service was observed
RUNNING during the investigation and was not modified by this WIP.

**Completion gate:** STOP-LINE remains open until the identity contract and
corrected E5 ratio are accepted. Issue #29 remains open.
