# ETW-FILE-DEDUPE-001 — stop producing the duplicate NameCreate lane (issue #29)

**Patch ID:** ETW-FILE-DEDUPE-001
**Flow ID:** QLOSS / #29 (pipeline ingress admission → host telemetry producers)
**Target HEAD:** `c0f4b1c`
**Evidence level (this record at write time):** E2 (source + unit) — E5 result appended in §7

## Why

#29 closes on "zero drops at sustained 4,000 FIM file-ops/s". The measured
ceiling of this build was 3,229.5 op-sets/s clean vs 4,008.6 op-sets/s lossy
(`HOST-WINDOW-003` §6). The owner named two acceptable fixes: stop producing
the duplicate lane, or give it capacity. This patch does the first.

Root cause is production duplication, not consumer starvation:

- The kernel minifilter already emits one `capture_fim` record per
  `IRP_MJ_CREATE` completion (`drivers/minifilter/aegis_minifilter_file.c`).
- The ETW Kernel-File provider emits `NameCreate` (opcode `0x0A`) for the same
  file open (`src/pipeline/telemetry_threads.zig`, `classifyEtwEvent`).
- Measured at 4,008 op-sets/s: all 15,990 drops were `capture_etw`
  (`minifilter_pipeline_dropped = 0`), i.e. the duplicate lane lost events
  while the authoritative lane stayed clean.

One op-set is open+write+close+unlink, so it produced ~4 host events
(ETW NameCreate + ETW Write + ETW NameDelete + minifilter create). Removing the
duplicate brings that to ~3 and keeps the writes/deletes the minifilter does
**not** emit.

## Old flow → new flow

**Old:** minifilter `IRP_MJ_CREATE` → `capture_fim` (kept)
        ETW `NameCreate` → `capture_etw` → `fim_change` (duplicate, queued)

**New:** minifilter `IRP_MJ_CREATE` → `capture_fim` (kept)
        ETW `NameCreate` → suppressed + counted (`name_create_deduped`)
        ETW Write/NameDelete/Registry/Process unchanged

## Scope guards (why this is not a coverage cut)

| Guard | Behaviour |
|---|---|
| Minifilter gate | Suppress only while `g_minifilter_state == .ok`; a host without the driver keeps full ETW file coverage |
| Per-record check | A minifilter disconnect restores the ETW lane on the next record, not the next restart |
| Opcode exactness | Only `0x0A`; Write (`0x10`) and NameDelete (`0x0B`) are never deduped (the minifilter does not emit them) |
| Provider exactness | Kernel-File GUID only |
| Operator kill switch | `AEGIS_ETW_NAME_DEDUPE=0`; default `on`, only the literal `0` disables |
| Accounting | `queue.stats.etw.name_create_deduped` — observed = pushed + deduped, never silent |

## Files changed

| File | Change |
|---|---|
| `src/pipeline/telemetry_threads.zig` | `EtwClasses.name_create_deduped`; `parseNameDedupeEnv`; `shouldDedupeNameCreate`; per-record gate in `etwCallback`; startup toggle + two tests |
| `src/control/handler_registry.zig` | `queue.stats` `etw` block exposes `name_create_deduped`; test pins the field |
| `tools/aegisctl.py` | `queue` row renders `dedupe=` only when the daemon reports it (older daemons byte-identical) |
| `tests/tools/test_aegisctl_queue.py` | new render test |

## Invariant

1. `etwCallback` never suppresses a record unless
   `g_minifilter_state == .ok` at that record.
2. Only `(Kernel-File GUID, 0x0A)` can be suppressed.
3. Every suppressed record increments a published counter.
4. With `AEGIS_ETW_NAME_DEDUPE=0` the callback is byte-identical to the
   previous behaviour.

## Build / test result (E2)

```
zig build        EXIT=0
zig build test   EXIT=0
pytest tests/tools/test_aegisctl_queue.py   14 passed
```

## Remaining risk

- If a real workload has opens the minifilter misses but ETW catches, those
  creates are now invisible while the minifilter is healthy. The minifilter
  emits on every successful `IRP_MJ_CREATE` completion, so the residual gap is
  the kernel ring's own drop counter (`minifilter_ring_dropped`), which is
  published and must stay 0 for the dedupe to be justified.
- The dedupe is measured only on this host; a host with the minifilter present
  but idle (no FIM rules) would rely on the same `ok` state. The gate is
  connect-state, not event-flow-state.
