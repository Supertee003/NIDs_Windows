# Native Readiness Phase

## Current verified result

The current fresh runtime reached the complete core security path:

```text
sensor pipe -> canonical event queue -> signature detection -> policy match
-> Rust PEP decision=block -> audit trace
```

The observed event carried a non-zero event ID, non-zero rule identity, source/destination metadata, TCP protocol, policy ID, and PEP request ID.

## Remaining capability gates

| Capability | Current evidence | Interpretation |
|---|---|---|
| Core sensor and detection | Passed in latest runtime log | Ready for synthetic detection regression |
| Rust PEP | Passed; enforcement mode active | Ready for PEP decision validation |
| C++ bridge | Loaded and initialized | Ready |
| UDP brain | Active on 127.0.0.1:9999 | Ready |
| WFP driver/device | `ERROR_FILE_NOT_FOUND` for `\\.\AegisWfpDevice` | Driver/device installation or service binding is missing; do not claim kernel enforcement |
| ETW | `aegis_etw_start rc=-1` | Native ETW/session/provider prerequisites are not ready |
| FIM | Native watcher start failed for System32 and SysWOW64 | FIM is degraded; source now refuses to publish ready when zero watchers start |
| Registry | Thread started | Requires event-generation validation |

## Source correction in this phase

`FimWatcher.startAll()` now returns `error.NoWatchersStarted` when every native watcher fails. This prevents the telemetry thread from publishing `fim_ready=true` for a worker that has no live handle.

## Next order of work

1. Rebuild the fresh binary and verify the FIM readiness field is false when native starts fail.
2. Run the sensor-only regression and record detection, policy, PEP, audit, and forensic counters.
3. Build/install the WFP user/kernel components in an elevated isolated Windows test environment; verify the device path and service state.
4. Enable and validate ETW session startup with an elevated test account and clean session-name handling.
5. Validate FIM helper handles independently on a disposable test directory before System32.
6. Only after those gates pass run enforcement and host-telemetry tests.

No status is upgraded to healthy by masking an adapter error.
