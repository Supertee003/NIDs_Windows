# POST-SOAK-PATCHES — three ready patches for 2026-11-15T22:20:15

**Created:** 2026-11-14
**Why they wait:** every one of them touches `src/` or `build.zig`, both of which
are in `RUNTIME_PATHS`. A commit there makes the running 24 h soak stale, so the
work is prepared rather than applied.

Each is written so the window's end is mechanical, not investigative.

---

## 1. BUILD-NETINT-001 — one line in `build.zig`

`zig build test-network-integration` fails at HEAD:

```
src\tests\federation\federation_tcp.zig:5:17: error: import of file outside module path
Build Summary: 0/3 steps succeeded; 1 failed
```

`build.zig:218` roots the step at `src/tests/federation/`, so the test's
`@import("../../federation/federation_tcp.zig")` is illegal in Zig 0.13.

**Patch:** change that step's `root_source_file` to
`b.path("src/federation/federation_tcp.zig")` (the module under test runs its own
tests when it is the root; the aggregator file only imports and asserts `true`).

**Verify:** `zig build test-network-integration` exits 0. No runtime behaviour is
touched; no evidence level is claimed beyond the step running.

## 2. L7-JOIN-001 — the missing test, in `src/`

Nothing joins a `Rules.json` pattern to a nose-decoded frame (`L7-NO-JOIN-001`),
so L7 detection is E2 by construction only.

**Patch:** a test beside `src/pipeline/event_queue.zig`'s v3 gate test:

1. load a tiny rules document containing `R0056`'s `match_pattern` (`' OR 1=1`)
   through `rule_loader.loadRulesInto`;
2. build a v3 frame whose payload carries that string;
3. `pushDecodedFrame(&frame, frame.payload)`, pop the queued event;
4. run `active_ac.matchFirst(queued.payload[0..payload_len])` and assert the rule
   id is `R0056`'s id and that the event would take the `.signature_match` path.

**Why it is not enough:** it proves the join inside the process. Whether a real
SQLi request on a real interface raises R0056 stays a lab-interface question
(`L7-NO-JOIN-001`'s second half), and no test may claim that from this.

## 3. READY-PROMOTION-001 — the state machine (already planned)

See `analysis/current-head/READY-PROMOTION-PLAN-20261114.md`. That plan already
carries the patch declaration, the hysteresis rule, the five tests, the risks and
the rollback. It also requires the elevated reinstall and a `clean_host_e5`
rerun, because after it lands the installed binary is older than source — a
build/runtime mismatch is a STOP-THE-LINE trigger.

## Order, and why

1. **BUILD-NETINT-001** first: one line, no runtime effect, and it restores the
   step that would catch the next broken import.
2. **L7-JOIN-001** second: adds the join to the unit graph.
3. **READY-PROMOTION-001** last: it changes runtime behaviour, needs the
   reinstall, and invalidates the soak it is waiting on. Its completion gate
   includes restarting the 24 h window from the new build.

Each lands as its own patch transaction with its own evidence entry; none of them
may be folded into another.
