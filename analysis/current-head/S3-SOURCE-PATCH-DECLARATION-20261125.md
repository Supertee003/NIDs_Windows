# S3 Source Patch Declaration — cross-process producer identity

- **PATCH-ID:** `S3-PRODUCER-IDENTITY-001`
- **FLOW-ID:** `NOSE-CAPTURE-V3 -> ZIG-PIPE-INGRESS -> QUEUE -> ALERT/HEALTH EVIDENCE`
- **TARGET HEAD:** `377581e6dc8b8485fe140fe5d6fbfcb4ce897694` (records commit over build source `4bc8244`)
- **TARGET FILES:** `nose/capture.go`, new `nose/producer_identity.go`, new Go tests,
  `src/contract/canonical_event.zig`, new `src/capture/producer_identity.zig`,
  `src/capture/nose_pipe_reader.zig`, `src/pipeline/runtime_state.zig`,
  `src/pipeline/event_queue.zig`, `src/pipeline/event_processor.zig`,
  `src/forensic/alert_log.zig`, `src/control/state_machine.zig`, `src/all_tests.zig`,
  `shared/protocol/wire_v3.md`.
- **TARGET SYMBOLS:** `newLiveCaptureProvenance`, `issueProducerGeneration`,
  `nextCaptureSequence`, `validateV3Envelope`, `producer_identity.Guard`,
  `readClientLoop`, `recordNoseFrameDrop`, `pushDecodedFrameDetailed`, `QueuedEvent`,
  `formatAlertLine`, `healthJson`.
- **IN-SCOPE:** durable per-interface restart generation issued once by Go Nose;
  dedicated monotonic capture sequence; semantic validation and duplicate/regression
  rejection at Zig ingress; bounded identity tracking; additive queue sidecar and
  alert/health evidence; E2 tests in Go and Zig.
- **OUT-OF-SCOPE:** `CanonicalEvent` wire layout, existing golden vector bytes, rule
  IDs/match patterns, policy hash, FFI ABI, host effects, Windows E5 live capture,
  cross-machine clock synchronization, forensic 4 KB ring ABI.
- **CONTRACT IMPACT:** tightens documented provenance semantics without changing bytes.
  v1/v2 and metadata-only v3 frames remain accepted as legacy; provenance-bearing v3
  frames must carry nonzero tuple and monotonic sequence per producer key.
- **ABI IMPACT:** none on wire or FFI. Additive in-memory `QueuedEvent` field and
  additive NDJSON/health keys only.
- **AUTHORITY IMPACT:** Go Nose owns producer identity issuance; Zig ingress owns
  acceptance/dedup. No policy, PEP, or host-effect authority changes.
- **STATE IMPACT:** a small operator-visible state file in the user config directory
  (overridable by `AEGIS_NOSE_STATE_FILE`) holds monotonic per-interface generation.
  A stale lock or unwritable state fails capture startup closed. Zig guard is a bounded
  64-entry ring with deterministic eviction counted in health.
- **TEST IMPACT:** Go tests pin generation increment, per-interface isolation, stale
  lock failure and dedicated sequence increments. Zig tests pin semantic validation,
  duplicate/regression rejection, cross-generation acceptance, gap visibility and
  bounded eviction. Existing codec golden bytes stay unchanged.
- **EVIDENCE IMPACT:** new E2 evidence record after verification; old v3 E5 evidence
  remains HISTORICAL. No E3/E4/E5 claim from this patch.
