# Patch transaction — RULE-COVERAGE-001

## Declaration (before patch)

```
PATCH-ID:            RULE-COVERAGE-001
FLOW-ID:             DETECTION-L4-KERNEL
TARGET HEAD:         f0baadf9205a69ea0fc3e27a26eb7968e71cbb40 (worktree, detached)
BUILD SOURCE:        f4cde3c503fd8b696183751a608b999768caa769 (before patch)
TARGET FILES:
  drivers/wfp_callout/aegis_wfp.h
  drivers/wfp_callout/aegis_wfp_callout.c
  drivers/wfp_callout/aegis_wfp_payload.h
  src/policy/wfp_ioctl.zig
  src/capture/wfp_telemetry.zig
  src/pipeline/event_processor.zig
  tests/wfp/wfp_payload_slice_test.c
TARGET SYMBOLS:
  AEGIS_TCP_FLAGS_MASK / AEGIS_TCP_FLAGS_PRESENT
  aegis_wfp_tcp_flags_from_header
  AegisWfpEmitRecord
  wfp_ioctl.WfpEventHeader.tcp_flags_meta / wfpTcpFlags
  wfp_telemetry.ParsedRecord.tcp_flags / parseRecord / decodedFrame
  event_processor.processEvent L4 predicate gate
IN-SCOPE:
  Carry kernel-observed TCP flags from outbound WFP transport headers through
  the existing 48-byte header reserved word, the additive ContextFlags lane,
  the in-memory queue sidecar, into the L4 matcher so FLAGS rules can evaluate
  on WFP-sourced rows. PROTO rules can evaluate on either network source.
OUT-OF-SCOPE:
  Wire layout change, AEGIS_EVENT_HEADER size/offset change, driver install,
  service restart, topology change, host effects, WFP enforcement, signature
  re-sign, source changes to other rule layers, R2003 FP/FN (next slice).
CONTRACT IMPACT:
  Additive semantic reuse of AEGIS_EVENT_HEADER.reserved (@32, size unchanged)
  and CanonicalEvent.ContextFlags bits 16..24 (already defined). No wire-v*
  change; all codecs remain byte-identical.
ABI IMPACT:
  Driver<->consumer header word gains named meaning; layout pins added at
  @offsetOf(..., "tcp_flags_meta") == 32. Rust PEP treats records as opaque
  bytes and needs no rebuild for this semantic change.
AUTHORITY IMPACT:
  None. Zig remains the sole detection-verdict authority; WFP callout remains
  fail-open/observe-only; no host effect.
STATE IMPACT:
  None persistent. Queue sidecar is per-event in-memory only.
TEST IMPACT:
  Added C pure-helper test (6 cases), Zig header-layout/flags test, Zig
  WFP-record->queue->L4 test. Full unit + out-of-unit suites run.
EVIDENCE IMPACT:
  +1 E2 entry, no E-level promotion. E5 Windows proof still required for the
  driver change before any release claim.
```

## Production (after patch)

```
PATCH-ID:            RULE-COVERAGE-001
FLOW-ID:             DETECTION-L4-KERNEL
TARGET HEAD:         f0baadf9205a69ea0fc3e27a26eb7968e71cbb40
FINAL HEAD:          (recorded at commit time)
FILES CHANGED:       9 source/test files + this record + the 23-rule matrix + EVIDENCE_INDEX.json
OLD FLOW -> NEW FLOW:
  WFP row -> header reserved=0 -> queue tcp_flags=0 -> L4 gate skipped
  ==>
  outbound WFP TCP -> header.reserved(PRESENT|flags) -> ContextFlags lane ->
  queue tcp_flags -> L4 FLAGS/PROTO predicates; inbound/non-TCP stays null.
INVARIANT:
  Detection-only, no host effect, 48-byte header stride, one runtime,
  no wire change, no silent "flags=0" evidence.
BUILD RESULT:
  zig build                              PASS (exit 0)
  zig fmt --check (all touched .zig)     PASS
TEST RESULT:
  zig unit suite                         2109 passed / 11 skipped / 0 failed
  zig out-of-unit suite                  1234 passed / 0 failed
  C WFP helper suite                     6 cases PASS
  pytest contract + vector coverage      15 passed / 3 skipped
WINDOWS RESULT:
  Not E5. Driver helper compiled with zig cc and unit-tested off-host.
  Full WDK driver build and Windows host verification NOT run in this
  worktree (would require install/restart, forbidden while soak runs).
EVIDENCE LEVEL:
  E2 (unit + contract proof) + E1 (static/contract inspection). Not E3/E5.
EVIDENCE ARTIFACTS:
  analysis/current-head/RULE-COVERAGE-001-PATCH.md
  analysis/current-head/RULE-COVERAGE-001-MATRIX.md
  tests/wfp/wfp_payload_slice_test.c
  src/policy/wfp_ioctl.zig (layout + flags tests)
  src/capture/wfp_telemetry.zig (record->queue->L4 test)
  src/windows/etw_realtime.zig (CommandLine TLV fixture)
  src/pipeline/rule_loader.zig (R2003 positive + FP/FN negative controls)
ROLLBACK:
  Revert the 7 source/test files; no host state to revert; no binary was
  installed. `git revert <commit>` in this worktree if committed.
REMAINING RISK:
  - Inbound WFP still has no TCP flags evidence by WFP design; exact-flags
    rules cannot fire on inbound kernel rows. PROTO rules can.
  - WFP rows remain shadow while Go Nose is primary (source_arbiter), so
    coverage gain only manifests on kernel-primary or AEGIS_CAPTURE_SPLIT=1.
  - Full WDK driver build/E5 host proof pending.
  - FN-1 remains an accepted host-sensor limitation (no CommandLine in
    ProcessStart v0..v4 on this host); no fake positive was created.
  - DETECTION_VALIDATION.md §5 FP-1 row is stale (says Open); code and its
    own E5 record prove CLOSED. Correction belongs in the records tree.
OPEN BLOCKERS:
  - Owner decision on soak disposition (v1.1 close vs fresh window).
  - Owner authorisation to commit source (needed before truth rebaseline).
  - WDK build + authorized Windows host evidence for the driver change.
COMPLETION GATE:
  Slice 1 COMPLETE at E2: 23/23 catalog + evaluable coverage, L4 WFP gap
  closed, FP-1 reconciled as CLOSED-E5, FN-1 explicit and unmasked, regex
  ownership pinned. Not E5; board remains 5/6; no tag/publish.
TRUTH STATE:
  tools/truth.py verify = TRUTH_INVALID is CORRECT here: uncommitted source
  is never current truth. Maps stay stamped f4cde3c; rebaseline after commit.
```
