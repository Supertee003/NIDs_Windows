# S3 Producer Identity Evidence — 2026-11-25

## Patch transaction

- **PATCH-ID:** `S3-PRODUCER-IDENTITY-001`
- **FLOW-ID:** `NOSE-CAPTURE-V3 -> ZIG-PIPE-INGRESS -> QUEUE -> ALERT/HEALTH EVIDENCE`
- **TARGET HEAD:** `377581e6dc8b8485fe140fe5d6fbfcb4ce897694` (records commit over S2 build source `4bc8244`)
- **SOURCE HEAD / FINAL BUILD SOURCE:** `f1f89c183ee86410dbfdc748155dc3d22c086420`
- **COMMIT:** `f1f89c1 feat(capture): durable v3 producer identity admission (S3)`
- **EVIDENCE LEVEL:** `PASS_E2` (unit + pure component tests only)

## Old flow -> new flow

**Old:** Go Nose generated a synthetic v3 provenance tuple (`generation=1`) and a
sequence derived from the base event counter; Zig checked duplicate/non-monotonic
`event_id` per pipe connection. Restart identity could alias, and no v3 tuple
semantics were enforced at ingress.

**New:** Go Nose issues a durable per-interface generation under an exclusive
lock (`AEGIS_NOSE_STATE_FILE` override, otherwise user config dir) and stamps a
dedicated `capture_sequence` in the v3 envelope. Zig validates that a
provenance-bearing tuple is complete/nonzero, rejects exact replay and
regression before queue admission, counts gap/eviction visibly, and carries the
admitted tuple additively into alert evidence and health counters.

## Invariant

Producer identity is acquisition evidence only. It never creates a trust
verdict, policy decision, PEP authority, host effect, or enforcement claim.
Legacy v1/v2 and metadata-only v3 frames remain byte-valid and are admitted as
before; only provenance-bearing v3 frames make identity claims.

## Files changed

`nose/capture.go`, `nose/producer_identity.go` (new),
`nose/producer_identity_test.go` (new), `src/contract/canonical_event.zig`,
`src/capture/producer_identity.zig` (new), `src/capture/nose_pipe_reader.zig`,
`src/pipeline/runtime_state.zig`, `src/pipeline/event_queue.zig`,
`src/pipeline/event_processor.zig`, `src/forensic/alert_log.zig`,
`src/control/state_machine.zig`, `src/all_tests.zig`,
`shared/protocol/wire_v3.md`, `CONTRACT_MAP.json`, and the S3 patch declaration.

## Verification actually run

| Command | Result |
|---|---|
| `gofmt -w nose/producer_identity.go nose/producer_identity_test.go nose/capture.go` | exit 0 |
| `cd nose && go test ./...` | `ok aegis-nose 9.453s` |
| `cd nose && go vet ./...` | exit 0 |
| `zig build --cache-dir D:\aegis-tmp\s3_zig_cache --global-cache-dir D:\aegis-tmp\s3_zig_global test` + direct `test.exe` | `2154 passed; 10 skipped; 0 failed` |
| `zig build` | exit 0 |
| `python -m pytest tests/ tests/e2e -q` | `2 failed, 1510 passed, 1 skipped, 27 subtests passed` |
| `python -m pytest -q -p no:cacheprovider -m "not host_live"` | exit 0 |
| `python tools/rebuild_truth.py` | exit 0 |
| `python tools/truth.py verify` | `TRUTH_VALID` at build source `f1f89c1` |

Logs: `D:\aegis-tmp\s3_zig.log`, `D:\aegis-tmp\s3_zig_direct.log`,
`D:\aegis-tmp\s3_zig_build.log`, `D:\aegis-tmp\s3_pytest.log`,
`D:\aegis-tmp\s3_pytest_nohost.log`, `D:\aegis-tmp\s3_truth_rebuild.log`,
`D:\aegis-tmp\s3_truth_verify.log`.

### Pin coverage

- Go E2 pins: generation advances `1 -> 2`, per-interface isolation, stale lock
  fails closed without creating state, configured state path, dedicated
  monotonic sequence.
- Zig E2 pins: complete-tuple validation in `validateV3Envelope`, legacy/meta
  acceptance, duplicate/regression rejection, gap visibility, generation change
  makes reused sequence distinct, 64-key bound with counted eviction, identity
  drop cause counter, additive alert NDJSON keys, additive health keys.

## Full-suite failures (not hidden)

`tests/integration/test_e6_attack_burst.py::test_a_localhost_port_scan_is_captured_and_scored`
and
`tests/integration/test_e6_l4_scan_detection.py::test_a_syn_scan_is_tagged_by_an_l4_rule`
failed. Both are `host_live` loopback-capture E6 tests against the already
running daemon/Nose processes, which predate this source commit. They are NOT
claimed as S3 proof and NOT claimed as an S3 regression. The CI-equivalent
`-m "not host_live"` run is clean.

## Limitations and open proof

- No E3/E4/E5 run was performed against rebuilt `aegis_nids.exe` and
  `aegis-nose.exe`. Live current-build duplicate/replay denial remains
  `NOT_PROVEN`.
- The Zig guard is process-local and bounded to 64 producer keys; eviction is
  counted, never silent. A daemon restart resets the guard, but the durable Go
  generation prevents a restarted Nose from reusing the same tuple.
- The state file lives in the per-user config directory unless
  `AEGIS_NOSE_STATE_FILE` is set. A stale lock or unwritable state fails capture
  startup closed; no fallback to generation 1 is allowed.
- No `CanonicalEvent` wire layout, golden vector, rule ID, policy hash, FFI ABI,
  authority, or host-effect change was made.
- Detection matrix remains NOT RE-MEASURED at this source (last measured
  `f4cde3c`). Full current-head Windows E5 / kernel IDS qualification remains
  `NOT_PROVEN`. Soak/install/signing/E6/E7 remain OPEN.

## Rollback

Revert source commit `f1f89c1`; then rebaseline machine maps and re-record
digests at the restored build source. No host state outside the dedicated
user-config producer generation file is created by this patch.

## Completion gate

`PASS_E2` for the source-level producer-identity gap only. Live E3/E5,
detection matrix re-measurement, soak/install/signing/E6/E7 stay OPEN and are
not implied by this record.
