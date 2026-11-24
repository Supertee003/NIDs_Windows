# MASTER AUDIT — P8 / issue #44 E3 isolated `-inject` proof (2026-11-24)

**RECORDS HEAD AT READ:** `ba3daae` (pre-patch); new records commits follow this transaction.
**TARGET BUILD SOURCE:** `e406cbb3512b4faae8441e9f1eb70b481971c75c`
**SOURCE COMMIT AFTER PATCH:** `03bb86d98ea5925170157b6d0f9b63ed12f4c858`
**STATUS:** PASS_E3 — exact-delta harness executed on a real named pipe, no host-effect or wire change.

---

## PATCH DECLARATION

```
PATCH-ID:             P8-I44-E3-ISOLATED-INJECT
FLOW-ID:              nose ingress -> pipe reader -> canonical decoder -> queue -> authoritative counters
TARGET HEAD:          ba3daae (build source e406cbb)
TARGET FILES:         src/capture/nose_pipe_reader.zig
                      src/tests/cli/nose_pipe_e2e_cli.zig
TARGET SYMBOLS:       createPipeServer(pipe_name), runPipeReaderLoopNamed(stopSignal, pipe_name),
                      runPipeReaderLoop(stopSignal) [unchanged production entrypoint],
                      connectedClient(), pipeNameZ(), injectExactDeltaCases(pipe_name)
IN-SCOPE:             internal pipe-name seam; harness CLI `-pipe` option; real exact-delta execution
OUT-OF-SCOPE:         wire layout, golden vectors, rules, authority, host effect, WFP, soak, release identity
CONTRACT IMPACT:      NONE — canonical wire and pipe byte format unchanged
ABI IMPACT:           NONE
AUTHORITY IMPACT:     NONE — same reader, same counters, same single-instance authority
STATE IMPACT:         NONE — default runtime binding remains \\.\pipe\aegis_nose
TEST IMPACT:          harness now runnable without displacing a live daemon; all existing tests retained
EVIDENCE IMPACT:      one E3 entry added; build source advanced e406cbb -> 03bb86d; digests re-stamped
```

## WHY THIS SLICE EXISTS

The issue #44 closeout (`e406cbb`) documented the `-inject` harness as compiled and
source-pinned but **not run**, because the host had a live LocalSystem `AegisNids`
service and Go Nose owning `\\.\pipe\aegis_nose`, and this session is not
administrator (`sc.exe sdshow AegisNids` grants `WP` only to `SY` and `BA`;
interactive users have `CC/LC/SW/LO/CR/RC`). Stopping the service was therefore
not possible and would also have been a disruptive host action.

This slice adds an explicit-name seam to the same production reader loop so the
harness can own its own single-instance pipe (`\\.\pipe\aegis_nose_i44`) while the
live daemon keeps the canonical pipe. No frame bytes, decoder, counter or
authority behavior changed.

## FINDINGS AND REPLACEMENTS

| # | Current text/code before patch | Reason | Replacement |
|---|---|---|---|
| F1 | `const PIPE_NAME` + `fn createPipeServer()` hardcoded the single name; `runPipeReaderLoop` was the only entrypoint | A real named-pipe proof required displacing the live LocalSystem daemon; the session cannot stop it | `DEFAULT_PIPE_NAME` retained as the production default; `createPipeServer(pipe_name)` and `pub fn runPipeReaderLoopNamed(stopSignal, pipe_name)` added; `runPipeReaderLoop` delegates to the named form with the unchanged default |
| F2 | harness `openClient()`/`waitForPipe()` hardcoded `\\.\pipe\aegis_nose` | No isolated run possible without service downtime | `-pipe <ascii-last-segment>` parses a private pipe name, converted once to UTF-16Z by `pipeNameZ`; reader thread and client use the same name |
| F3 | harness connected, wrote and closed immediately | First real run produced zero deltas: the NOWAIT server polls `ConnectNamedPipe` every 50 ms, so a connect-write-close in the same instant was never observed | `connectedClient()` keeps the handle open for 250 ms after connect (matching the long-lived Go Nose client) before writing; inter-case gap raised to 250 ms |
| F4 | `connectedClient()` initially called itself after a broad `replaceAll` | Infinite recursion → `Stack Overflow` on the first instrumented run | Corrected to call `waitForPipe(pipe_name, 5_000)`; recompiled and re-ran green |

## OLD FLOW → NEW FLOW

```
OLD:  runPipeReaderLoop -> createPipeServer() -> \\.\pipe\aegis_nose (fixed)
      harness -inject -> same fixed name -> cannot run while daemon owns pipe

NEW:  runPipeReaderLoop -> runPipeReaderLoopNamed(DEFAULT_PIPE_NAME)  [production unchanged]
      harness -pipe aegis_nose_i44 -> runPipeReaderLoopNamed(private)
                                  -> createPipeServer(private)
                                  -> real client writes failing frames
                                  -> authoritative + local counters asserted exactly
```

**INVARIANT:** the canonical runtime still binds `\\.\pipe\aegis_nose` with
`nMaxInstances=1` and the same SDDL; only an explicitly named test instance differs.

## REAL EXECUTION PROOF (E3)

Command (compiled with `src/` as module root via a temporary `src/`-root wrapper,
wrapper removed after compile):

```
zig build-exe src/i44_e3_wrapper.zig -femit-bin=D:\aegis-tmp\i44_e3_check.exe
i44_e3_check.exe -inject -pipe aegis_nose_i44d -seconds 2
```

Observed (full transcript: `D:\aegis-tmp\i44_e3_inject4.txt`):

```
[E2E] pipe=\\.\pipe\aegis_nose_i44d
info: [NOSE PIPE] pipe server created, waiting for client...
info: [NOSE PIPE] client connected
[INJECT] close-before-payload OK: +1 midframe, +1 pipe error
error: [NOSE PIPE] absurd frame length 65537: dropping connection to resync
[INJECT] absurd-length OK: +1 framing, +1 pipe error
warning: [NOSE PIPE] rejected frame length: 108, expected 109/133 or v3 165..1189
debug: [NOSE PIPE] canonical event submitted: event_id=62541
[INJECT] drain-then-valid OK: +1 framing, +1 submitted, no pipe error
info: [NOSE PIPE] reader loop exiting (read=1 drop=3 submitted=1)
[E2E] reader frames_read=1 submitted=1 rejected=0 dropped=3 pipe_errors=2
inject_exit=0
```

Exact deltas asserted by `waitForDelta()` on every counter:
1. `close-before-payload`: total +1, midframe +1, pipe_errors +1, local dropped +1, local pipe_errors +1.
2. `absurd-length`: total +1, framing +1, pipe_errors +1, local dropped +1, local pipe_errors +1.
3. `drain-then-valid`: total +1, framing +1, submitted +1, local dropped +1, no pipe error.

The live service was **not** touched: `sc.exe query AegisNids` still reported
`STATE : 4 RUNNING` and PIDs `aegis_nids 82112`, `aegis-nose 58924` before and
after the run.

## VERIFICATION

```
zig build test                         -> exit 0
zig build                              -> exit 0
python -m pytest -q -m "not host_live" -> 1486 passed, 1 skipped, 18 deselected, 27 subtests passed
python tools/truth.py verify           -> TRUTH_VALID @ 03bb86d (after rebaseline)
python tools/release_engineering.py --verify -> 674/674 digests (after refresh)
python scripts/doc_checker.py          -> 0 FAIL, 0 WARN
python scripts/check_summary.py        -> SUMMARY_VALID
python D:\aegis-tmp\check_links.py     -> BAD LINKS none
```

## EVIDENCE LEVEL AND LIMITS

**E3 (component integration) only.** Real named pipe, real production reader
loop, real decoder/queue path, exact authoritative counter deltas. **No E4/E5,
no Windows-host soak, no install, no signing, no production simulation.** The
harness runs in the harness process with a fabric sink; it does not exercise the
`AegisNids` service or the Go Nose producer, and it is not a loss-rate or
soak measurement. The private pipe name is a test seam, not a new ingress path.

No "zero loss ever" claim: the recorded 36.52 h soak remains the sole zero-loss
statement and is HISTORICAL at `a53eda8`. No `CanonicalEvent` wire-layout,
golden-vector, rule, authority, host-effect, re-key, tag or signature change.
Release identity remains `v1.1` / `466a226` / `a53eda8`, 6/6 gates PASS (0 open).

## ROLLBACK

Revert source commit `03bb86d` and its rebaseline/digest/evidence records
commits; `git revert <sha>` in reverse order restores `e406cbb` as build source
with the original E1/E2 closeout intact. No release artifact or published tag
is affected.

## COMPLETION GATE

PASS_E3 — real `-inject` exact-delta run green, full non-host suite green,
truth/digest/doc/link gates green at the new build source. Remaining risk: none
for the #44 counter-delta claim; E4/E5 still require an isolated host with the
service stopped and a real Nose producer, which is deliberately not claimed.
