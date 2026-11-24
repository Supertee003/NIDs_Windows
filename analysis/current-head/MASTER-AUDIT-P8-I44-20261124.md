# MASTER AUDIT — P8 / issue #44 observability source slice (2026-11-24)

**PATCH-ID:** `P8-I44-OBSERVABILITY`
**FLOW-ID:** nose ingress → queue → detection → health JSON → control API (issue #44 / F4 / F6 / F7)
**TARGET HEAD (build source before patch):** `2129dcd7a166ef47226a9ae4afd8144d787ebbf0`
**SOURCE COMMIT AFTER PATCH:** `e406cbb3512b4faae8441e9f1eb70b481971c75c`
**RECORDS COMMITS:** truth rebaseline `eae7631`, digest refresh `82873a7`, this addendum and its
`EVIDENCE_INDEX.json` entry (final records HEAD is the commit that lands this file).

## 0. Why this is a source patch

Issue #44 was filed as a STOP-THE-LINE "silent event loss" triage. Five source paths were
confirmed with exact line/counter evidence; the closure requires additive counters, a renamed
lifecycle input, new health/control API projections and source-pinning tests. Every change below
is in the source/build tree. This slice is **not** records-only and does not claim a higher
evidence level than E1/E2. It does not change the CanonicalEvent wire layout, golden vectors,
rules, authority, host effects, release identity, tag, signature or key.

## 1. Findings and replacements

| # | Path | Current text/code (before) | Why it fails | Replacement (after) | Acceptance criteria |
|---|---|---|---|---|---|
| 1 | `src/pipeline/event_processor.zig` consumer | `_ = state.g_pipeline_processing_errors.fetchAdd(1, .monotonic)` already existed but the detector `observe` calls had no failure counter | a failed detector observation was invisible to health; calling it "event loss" would be false because `processEvent` is infallible today | counted wrappers increment `g_correlator_observe_errors`, `g_anomaly_observe_errors`, `g_threat_tracker_observe_errors`; the event keeps flowing; a forced-allocation-failure test pins the delta | dedicated runtime counter exposed in health JSON + control API; no event-loss claim |
| 2 | `src/capture/nose_pipe_reader.zig` mid-frame payload `readExact()` failure | incremented only `g_reader_stats.pipe_errors` | `g_nose_pipe_errors` and `g_nose_frames_dropped` did not move, so the aborted frame was invisible to `data_loss_observed` | increments `g_reader_stats.pipe_errors`, `g_reader_stats.frames_dropped`, `g_nose_pipe_errors` and the `.midframe` cause atomically | payload read/connect error increments `g_nose_pipe_errors` + drop counter in the same patch |
| 3 | `src/capture/nose_pipe_reader.zig` `ConnectNamedPipe` handled-else errors | only the local `g_reader_stats.pipe_errors` moved | same invisible-loss class as #2 | routed through the same authoritative error/cause counters | same criterion as #2 |
| 4 | `nose/pipe_writer.go` capture-side drops | local `w.dropped` + stderr, no Zig counter | pre-pipe capture-side boundary is real but must not be silently merged into Zig counters | left as a **distinct boundary** and documented, not folded into `g_nose_frames_dropped` | distinct boundary preserved; no silent merge |
| 5 | `src/pipeline/runtime_state.zig` `g_nose_frames_dropped` comment/field | documented as "queue backpressure" while incremented for framing rejects, midframe aborts, shape refusals and capacity sheds | loss classes were conflated; health could not distinguish them | four exclusive diagnostic causes behind `recordNoseFrameDrop(cause)`: `framing`, `midframe`, `shape`, `capacity`; they sum to the parent counter and are pinned by a counter-sum test; never added to soak `LOSS_COUNTERS` | split by cause with distinguishable names; exact-delta test |
| 6 | `src/pipeline/event_queue.zig` shape gate | returned bare `false` | callers could not tell a shape refusal from a capacity shed | `DecodedFrameOutcome` + `pushDecodedFrameDetailed`; the old `pushDecodedFrame` bool facade is preserved for legacy callers | shape vs capacity distinguishable without breaking callers |
| 7 | `src/control/state_machine.zig` lifecycle input | cumulative `data_loss_observed` fed the stable-pairing decision | conflated cumulative health loss with fresh observed loss; renaming is required so the two semantics are not unified | input renamed `fresh_loss_observed`; health `state` may stay `DEGRADED` while lifecycle `runtime_state` returns `RUNNING` after clear samples | stable pairing kept; semantics not unified |
| 8 | health JSON / `tools/aegisctl/api/control_api.py` | no cause split, no detector-degradation object | operators could not see the new counters | additive cause keys and a separate `detector_degradation` object `{correlator_errors, anomaly_detector_errors, threat_tracker_errors}`; offline health projection updated; detector counters never feed `data_loss_observed` | every event-failure counter exposed in health JSON + control API |

**F4 dual submitter (`kernel_fallback` / `nose_stalled`)** is a deliberate stall-recovery overlap,
documented and retained; Nose is not gated off. **F6 detector failures** are detection-degradation
signals, not event loss: the event keeps flowing, the counters live in a separate health object,
and they are excluded from the soak tool's `LOSS_COUNTERS`.

## 2. Patch transaction / flow impact

```text
OLD  nose frame drop        -> one conflated g_nose_frames_dropped ("queue backpressure")
NEW  nose frame drop        -> framing | midframe | shape | capacity exclusive causes; sum pinned

OLD  midframe read failure  -> local pipe_errors only; no authoritative drop
NEW  midframe read failure  -> pipe_errors + frames_dropped + g_nose_pipe_errors + .midframe

OLD  detector observe error -> invisible; processEvent failure counted only generically
NEW  detector observe error -> named detector_degradation keys; event still flows

OLD  queue shape gate       -> bool false (shape and capacity indistinguishable)
NEW  queue shape gate       -> DecodedFrameOutcome; bool facade preserved

OLD  lifecycle input        -> cumulative data_loss_observed (semantics conflated)
NEW  lifecycle input        -> fresh_loss_observed (DEGRADED health / RUNNING runtime coexist)
```

**INVARIANT:** no wire byte, rule, authority, host effect, ABI, golden vector, release identity or
gate count changed. All changes are additive counters, a renamed internal input, disclosure
comments and E1/E2 tests.

**CONTRACT IMPACT:** none. `CanonicalEvent` layouts v1/v2/v3 and the golden `.bin` vectors are
byte-identical; no contract ID or version changed.

**ABI IMPACT:** none. No FFI signature, struct layout or ordinal changed.

**AUTHORITY IMPACT:** none. Detection-only PEP posture and no-host-effect rule unchanged; no
WFP mutation and no privileged IPC exposure added.

**STATE IMPACT:** additive counters and one renamed lifecycle input only. The four cause counters
are diagnostic subsets of `g_nose_frames_dropped`; detector counters are not event-loss state.

**TEST IMPACT:** 60 targeted pins passed; 1486 passed, 1 skipped, 18 deselected, 27 subtests in
the full non-host run. Exact delta proof: Zig counter-sum/forced-failure unit tests plus a real
named-pipe `-inject` harness compiled (not run against the live daemon).

**EVIDENCE IMPACT:** one E2 entry added; build source advanced `2129dcd` → `e406cbb`; 674 digests
refreshed; all truth maps restamped; frozen historical records untouched.

---

## 3. Verification proof

- `zig build test` -> exit 0.
- `zig build` -> exit 0.
- `cd nose && go build -o D:\aegis-tmp\aegis-nose-i44.exe .` -> exit 0, artifact present.
- E2E harness compile via `src/`-root wrapper -> exit 0 (`D:\aegis-tmp\i44_e2e_compile3.txt`).
- Targeted pin set (control/retry, soak verdict, capture arbitration, direction metadata, doc truth
  labels) -> `60 passed`.
- `python -m pytest -q -m "not host_live"` -> `1486 passed, 1 skipped, 18 deselected, 27 subtests passed`.
- `python scripts/check_summary.py` -> `SUMMARY_VALID`.
- `python scripts/doc_checker.py` -> `0 FAIL, 0 WARN, 23 total`.
- `python D:\aegis-tmp\check_links.py` -> `BAD LINKS: none`.
- `python tools/truth.py verify` -> `TRUTH_VALID @ e406cbb`.
- `python tools/release_engineering.py --verify` -> `674/674` artifacts, 0 missing.
- Exact-delta `-inject` pipe run -> **not executed on this host**. The AegisNids service and Nose
  were running (`aegis_nids` PID 82112, `aegis-nose` PID 58924) and owning `\\.\pipe\aegis_nose`;
  injecting failing frames there would disturb a live daemon. The harness is compiled and its
  assertions are source-pinned; it is marked ISOLATED HOST ONLY. No E4/E5 claim is made from it.

**WINDOWS RESULT:** not run at this source. No E5, E4, soak, install, signing or production
simulation is claimed. The recorded 36.52 h soak remains the only zero-loss statement and is
HISTORICAL at `a53eda8`.

**EVIDENCE LEVEL:** E1 (source/document inspection) + E2 (unit/pin proof). No higher level.

**EVIDENCE ARTIFACTS:** this file; `EVIDENCE_INDEX.json` entry `P8-I44-OBSERVABILITY-E2`;
`D:\aegis-tmp\i44_fullpytest2.txt`, `D:\aegis-tmp\i44_targeted2.txt`,
`D:\aegis-tmp\i44_zigtest2.txt`, `D:\aegis-tmp\i44_gobuild2.txt`,
`D:\aegis-tmp\i44_e2e_compile3.txt`, `D:\aegis-tmp\i44_truth2.txt`,
`D:\aegis-tmp\i44_refresh2.txt`, `D:\aegis-tmp\i44_doccheck2.txt`,
`D:\aegis-tmp\i44_summary2.txt`, `D:\aegis-tmp\i44_links2.txt`.

**ROLLBACK:** revert source commit `e406cbb` and its rebaseline/digest/evidence records commits;
frozen `v1.1` release identity is untouched. No config, key, tag or signature rollback required.

**REMAINING RISK:** the exact-delta `-inject` pipe proof is compiled and source-pinned but was not
run on a live host; an isolated-host run is still required for E3/E4. Go capture-side drops remain
a distinct pre-pipe boundary and are not merged into Zig counters. Detector allocation failures
are detection degradation, not event loss; no "zero loss ever" claim is made.

**OPEN BLOCKERS:** none for this slice. No E4/E5/soak gate may be closed from these results.

**COMPLETION GATE:** PASS (E1/E2). Build 0, targeted pins 60/60, full non-host 1486/1486, docs
0 FAIL, links none, TRUTH_VALID @ e406cbb, 674/674 digests. Release identity remains `v1.1` /
`466a226` / `a53eda8`, 6/6 gates PASS, no new tag/signature/key and no current-source E4/E5/soak
claim.
