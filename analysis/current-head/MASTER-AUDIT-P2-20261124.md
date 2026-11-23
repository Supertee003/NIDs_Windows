# Master Audit — Phase 2 (Protocol Integrity) / issue #44 observability slice

**Target HEAD:** `b796cff9eca3adf579b31beef75d9468aefd081a`
**Build source after this patch:** `9105ff56d3aa223fd7e0ff9c2e6e71b1d93771be`
**Date:** 2026-11-24
**Classification:** "ตรวจพบ" = confirmed in current source; "ต้องตรวจ Source" = suspicion requiring source proof; "แนะนำเพิ่ม" = recommended hardening.

---

## 1. STOP-THE-LINE handling (AGENTS.md)

`AGENTS.md` lists **Silent event loss** as a STOP-THE-LINE trigger. The read-only Phase 2 counter trace appeared to find a loss path at `src/pipeline/event_processor.zig:1258-1260`, so coding stopped and issue #44 was filed before any patch.

**Correction filed on the issue before coding:** the `processEvent` body (lines 252-723) contains zero `try`, zero `return error.`, zero `error.`; its only three `catch` sites are `catch null` (`:452`, `:474`, `:489`). The `!void` signature and the `catch |err| diag.warn(...)` at `:1258` are therefore **defensive-only** and unreachable today. Claiming that path as a confirmed P0 loss would have been overclaiming; issue #44 now records the correction. The trigger remains valid for the two pipe paths below.

---

## 2. This slice — confirmed findings and replacements (PATCH `P2-44-MINOBS-20261124`)

### P2-44-1 — unexpected `ConnectNamedPipe` error invisible to health · ตรวจพบ

- **File:line:** `src/capture/nose_pipe_reader.zig:337-343`
- **Current:** `g_reader_stats.pipe_errors += 1;` then sleep/continue. Local stats only.
- **Reason:** `src/control/state_machine.zig:407-434` computes `data_loss_observed` / `DEGRADED` exclusively from runtime counters. A non-handled connect error therefore never reaches health or the control API.
- **Replacement:** after the local increment, `_ = runtime_state.g_nose_pipe_errors.fetchAdd(1, .monotonic);`
- **Acceptance:** authoritative counter increments on that branch; source-inspected (E1). A Win32-injected unit test is not available on this host and is explicitly not claimed.

### P2-44-2 — aborted frame payload invisible to health · ตรวจพบ

- **File:line:** `src/capture/nose_pipe_reader.zig:414-418`
- **Current:** on `readExact()` failure: warn + `g_reader_stats.pipe_errors += 1;` + `break`.
- **Reason:** a valid 4-byte LE length header already committed the reader to a frame; the connection break is visible via `g_nose_connected=false`, but the lost frame has no loss counter.
- **Replacement:** increment both `g_nose_pipe_errors` (I/O) and `g_nose_frames_dropped` (lost frame), matching the existing resync precedent at `:392-393`.
- **Acceptance:** both counters increment on that branch; source-inspected (E1).

### P2-44-3 — `g_nose_frames_dropped` comment misnames the counter · ตรวจพบ

- **File:line:** `src/pipeline/runtime_state.zig:453` and the shadow-frame comment at `:454-456`
- **Current:** shadow comment says `distinct from g_nose_frames_dropped (queue backpressure)`; the counter itself has no comment.
- **Reason:** the counter is incremented for framing rejects (`nose_pipe_reader.zig:392,407`), aborted payload reads (new `:420`), and post-decode queue/shape/direction refusals (`:482`). "Queue backpressure" describes only part of that set.
- **Replacement:** doc comment listing all three classes and stating causes are not split here (issue #44 follow-up); shadow comment changed to `(the admission/loss counter)`.
- **Acceptance:** comment matches every increment site; no field rename (no health-schema break).

### P2-44-4 — defensive processing-error catch stays silent if it ever becomes live · แนะนำเพิ่ม

- **File:line:** `src/pipeline/runtime_state.zig:447` (new), `src/pipeline/event_processor.zig:1258-1260`
- **Current:** no counter; `diag.warn` only.
- **Reason:** currently unreachable (see §1), so this is hardening, not a proven loss. Instrumenting it costs one atomic and removes the possibility of a future silent loss.
- **Replacement:** `g_pipeline_processing_errors`; increment in the catch; explicit comment that it is defensive and stays at 0 today.
- **Acceptance:** counter is 0 in the current build; annotated as such in source, evidence, and control API projection.

### P2-44-5 — new counter must be observable · ตรวจพบ (gap closed)

- **File:line:** `src/control/state_machine.zig:416,429-431,462` and `tools/aegisctl/api/control_api.py:1068-1083`
- **Current:** no such health key or projection entry.
- **Reason:** a counter nobody can read does not close the trigger.
- **Replacement:** additive `data_integrity.pipeline_processing_errors` in daemon health; `data_loss_observed` gains `pipeline_processing_errors > loss_budget`; control API whitelist gains the key (older daemons still omit it, never fabricated as 0).
- **Acceptance:** new Zig test `healthJson exposes pipeline processing errors and degrades on them (issue #44)` asserts the field plus `DEGRADED`/`degraded:true` with all other loss counters at 0.

### P2-44-6 — Phase 1 evidence summary drift · ตรวจพบ (correction)

- **File:line:** `EVIDENCE_INDEX.json` → `evidence_level_summary.E1_count`
- **Current:** `41` while the `evidence` array contains 42 E1 entries after `MASTER-AUDIT-P1-20261124-E1` was added.
- **Reason:** the entry was appended without recomputing the derived summary; `tests/release/test_evidence_index_valid.py::test_level_summary_matches_entries` fails on HEAD `b796cff`. The Phase 1 claim of a fully green release suite was therefore too strong.
- **Replacement:** recompute the summary from the `evidence` section using `scripts/check_summary.py` rules (evidence only; `known_gaps` is a findings log).
- **Acceptance:** `python scripts/check_summary.py` exits 0 and the release test passes.

---

## 3. Flow: old → new

```
OLD  ConnectNamedPipe error / aborted payload  -> local g_reader_stats only -> health unchanged -> RUNNING possible
NEW  ConnectNamedPipe error                     -> g_nose_pipe_errors++       -> health data_integrity -> DEGRADED when > budget
NEW  aborted payload                            -> g_nose_pipe_errors++ + g_nose_frames_dropped++ -> same
OLD  processEvent catch (defensive)             -> diag.warn only             -> no counter
NEW  processEvent catch (defensive)             -> g_pipeline_processing_errors++ -> health -> DEGRADED when > budget
```

**Invariant:** detection-only posture; no host effect; no wire/golden-vector/rule/authority change; `loss_budget` semantics unchanged (`>` comparison, strict default 0); additive health key only; older readers ignore unknown fields.

---

## 4. Build / test result

| Gate | Result |
|---|---|
| `zig build` | success |
| `zig build test --summary all` (fresh caches) | **3367/3377 passed, 10 skipped** (baseline 3366/3376 → +1 new test) |
| `go test` targeted codec set in `nose/` | `ok aegis-nose` |
| Python release/runtime/security suites | see evidence entry; re-run after records rebase |
| C++ vector harness | unchanged source this slice |

**Note:** cached incremental `zig build test` reports only the newly executed step (2133 tests). The 3367 figure comes from a run with fresh `--cache-dir` / `--global-cache-dir`.

---

## 5. Evidence level and limitations

- **E2** for observability: the health JSON field and DEGRADED transition are asserted by a Zig unit test.
- **E1** for the two Win32 increment sites: source-inspected; no injected-frame test and no Windows host run in this slice.
- No E4/E5, no soak, no signed-candidate change, no Windows verification.
- No "zero loss ever" claim. The recorded 36.52 h soak window remains the only zero-loss statement.
- `g_pipeline_processing_errors` is expected to stay 0 in production today; a non-zero value would be new information, not a historical defect count.

---

## 6. Carry-forward — Phase 2 findings NOT in this slice

These were confirmed/read-only audited and are deliberately **not** patched here, so the current slice has one clear completion gate. They belong to separate slices.

### 6a. Protocol docs / machine map (`P2a`, records-only)

| # | File:line | ตรวจพบ | Required replacement direction |
|---|---|---|---|
| A1 | `shared/protocol/wire_v1.md:11,23,138` | active 125-byte framing claim; source uses 4-byte LE prefix (113/137/169..1193); 125 is legacy WEV1 | mark LEGACY WEV1, state active framing |
| A2 | `shared/protocol/protocol.md:10,21,69,78` | 125-byte active claim; reserved called zero-fill (actually G2-frozen identity+confidence); stale `core/wire_event.zig` path | HISTORICAL banner + correct reserved + `src/contract/wire_event.zig` |
| A3 | `shared/protocol/wire_v1.h:15-21` | legacy WEV1 header presented as wire frame | mark LEGACY, cite active framing |
| A4 | `CONTRACT_MAP.json:224,233` | machine map calls 125/149 bytes the active schema | distinguish legacy nominal from active prefix framing |
| A5 | `CONTRACT_MAP.json:147,181-185` | `control_ipc.zig` named as implementation; replay/nonce declared as consumed | point to active JSON control v2; state declared-but-**unenforced** on v2 |
| A6 | `shared/protocol/versioning.md:24-27,31-36` | "skip unknown trailing fields"/"add to reserved" contradicts exact-length fail-closed | HISTORICAL (superseded) marker |
| A7 | `wire_v1.md:5-7`, `protocol.md:7-8,97`, `wire_v1.h:5-6` | all five languages claimed byte-identical production codecs | Rust TBD; Python test-only/non-production; name implemented codecs |
| A8 | `CONTRACT_MAP.json:18-24` | language list contradicts :13 of the same map | align with actual codec status |
| A9 | `shared/protocol/control_protocol.md:5-6` | v1 FROZEN header above v2 ACTIVE section | top banner: v1 history, v2 active |

`INTERVIEW_PREP.md:17` ("declared-but-unenforced nonce") is **correct** and must not be changed into an enforced claim.

### 6b. Codec helpers (`P2b`, source change → new build source + full re-verify)

| # | File:line | ตรวจพบ | Replacement direction |
|---|---|---|---|
| B1 | `src/contract/canonical_event.zig:1624-1625` | comment "Extra trailing bytes" but asserts `buf[0..n-1]` (short frame); no real v3 trailing test in Zig | assert `n+1` rejection; separate short-frame case; add v3→v1 mutation |
| B2 | `nose/canonical.go:612-621` | exported `DeserializeV3` patches version to 1 at `:618` without pinning; direct call accepts forged version (dispatch is safe) | pin version 3 before patch + direct-call test |
| B3 | `shared/wire/wire_codec.h:501-508` | same version-pin gap in test harness | pin version 3 + forged-version case |
| B4 | `shared/wire/wire_codec.py:555`, `:112` | `<` instead of `!=` → trailing bytes accepted at frame/envelope helper layer | exact length + frame-level trailing test |
| B5 | `shared/wire/wire_codec.h:597-617` | `aegis_wire_decode_frame` omits v3 and uses `<`; **zero callers repo-wide** (git + filesystem grep) | delete or fix; never count as live coverage |
| B6 | `tests/contracts/event_vectors/event_vectors/vectors_metadata.json:218-237` | 9 vectors' SHA256/size match bytes but no test checks them | add digest verification test |

Golden vectors themselves are **OK**: 109/133/197/229/165 bytes, all SHA256 values recomputed and matched. Live codecs (Zig / Go / Go-FFI / C++ / Python reference) enforce exact length and fail closed on unknown version.

### 6c. Follow-ups to issue #44 (not in this slice)

- Split `g_nose_frames_dropped` by cause (framing / capacity / shape) or rename health fields; needs control API, dashboard, fixtures, maps in one patch.
- Add a Win32-injected counter-delta test for the two increment sites (E3), and surface `nose_frames_rejected` in CLI/dashboard.
- `nose/pipe_writer.go:155-157,173` capture-side drops stay local + stderr; recorded as a process boundary limitation, not merged across the pipe.

---

## 7. Completion gate

**PASS (E2 + E1 mix, as stated in §5).** No wire/rule/authority/release change. Build source advanced to `9105ff5`; machine maps and evidence index must be rebased before this gate is considered final.
