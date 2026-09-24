# EVENT-QUEUE-001 — Producer Reservation Safety Evidence

**PATCH-ID:** `EVENT-QUEUE-001-PRODUCER-RESERVATION`  
**FLOW-ID:** `ACQUISITION-TO-PIPELINE-QUEUE-001`  
**TARGET HEAD:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**FINAL HEAD:** pending commit; source patch is present in the working tree  
**Date:** 2026-09-17

## Scope

This vertical slice addresses only the producer reservation seam in `src/pipeline/event_queue.zig` and the queue-drop counter read path. It does not claim complete MPMC lock-free semantics, event identity correctness, shutdown drain, enforcement, or Windows system integration.

## Target files and symbols

- `src/pipeline/event_queue.zig`: `pushEvent`, producer reservation mutex, producer stress worker, conservation test.
- `src/pipeline/runtime_state.zig`: `g_queue_drops` declaration.
- `src/control/handler_registry.zig`: `eventsStats` and `eventsTail` queue-drop snapshots.
- `inventory.json` and `reference_map.json`: regenerated using `tools/generate_truth_artifacts.py`.

## Old flow → new flow

```text
OLD:
  producer -> load g_queue_head -> inspect tail -> write slot -> store g_queue_head
  (two producers could observe the same head and overwrite the same slot)

NEW:
  producer -> producer mutex -> load head/tail -> check capacity -> write slot
           -> publish head -> unlock
```

The consumer continues to use the existing queue mutex. This is intentionally a conservative serialized-producer implementation until a separately proven bounded MPMC algorithm is selected.

## Invariants

1. At most one producer reserves and publishes a head position at a time.
2. A full queue increments the drop counter atomically and returns `false`.
3. Health serialization loads one atomic queue-drop snapshot per response.
4. The stress test asserts `accepted events == popped events` after eight concurrent producers complete.
5. This patch does not invent or rewrite event identity; duplicates and restart epochs remain open risks.

## Contract and ABI impact

The queue function signatures are unchanged. The health JSON field name `queue_drops` is unchanged. No wire ABI is intentionally changed. `g_queue_drops` changes from a plain `u64` to an atomic `u64` implementation detail; readers now use an acquire load.

## Verification

Passed in sandbox:

```text
python3 -m unittest tests.runtime.test_lifecycle_authority tests.runtime.test_health tests.runtime.test_aegisctl -v
Ran 42 tests in 34.716s
OK
```

Passed:

- Python compilation for changed Python files.
- `git diff --check` for the targeted patch files.
- `tools/generate_truth_artifacts.py` completed and wrote `inventory.json` and `reference_map.json`.
- Target files and reports exist and are non-empty.

Not yet passed / not claimed:

- `zig fmt` and `zig build test` on Windows: the desktop session closed before returning output.
- `zig build` and compiled Zig stress test: no result is available.
- Windows host evidence: not run for this patch.
- `tools/truth.py verify`: correctly returned `TRUTH_INVALID` because nine current-head truth artifacts remain stale (`SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`, `CONTRACT_MAP.json`, `EVIDENCE_INDEX.json`, `build_truth.json`, `runtime_manifest.json`, `build_manifest.json`, and `AI_CONTEXT.md`).

## Evidence level

- **E1:** source/static patch inspection.
- **E2:** Python regression proof only.
- **Zig queue proof:** pending Windows Zig test result; do not treat the added test as passed until compiled output is captured.
- **No E3/E4/E5 claim.**

## Remaining risks

The producer mutex removes the identified head reservation race but serializes all producers and does not by itself prove complete acquire/release publication across every future change. Queue capacity/backpressure, event identity/deduplication, shutdown drain, forensic flush, and bridge spool ownership remain open. Truth maps must be regenerated after the patch is committed using a complete canonical generator pipeline.

## Completion gate

This patch is complete only after all of the following are captured:

1. Windows `zig fmt` succeeds.
2. Windows `zig build test` succeeds, including the eight-producer conservation test.
3. Existing runtime/control tests remain green.
4. Current-head truth artifacts are regenerated after commit.
5. Evidence index records this patch and its actual E-level.
6. Queue stress results are preserved as raw test output.

## Rollback

Revert the changes to the three source files and remove the added queue evidence file. Do not revert to an unsynchronized producer head reservation while retaining multi-producer claims.
