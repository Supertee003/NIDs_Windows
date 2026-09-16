# Native Gates Implementation Status

## Implemented in source

The WFP, ETW, FIM, and Registry boundaries were reviewed as separate capabilities rather than treating the daemon's RUNNING state as proof that every adapter is operational.

### WFP IOCTL

The read-only Zig IOCTL wrapper and C bridge use the same device path (`\\.\AegisWfpDevice`) and read-only telemetry contract. A missing device remains a real failure. Kernel enforcement is not claimed until the signed driver is installed, the service is running, and the device opens successfully.

### ETW

The native ETW helper now handles a stale session by stopping and recreating it, logs each provider-enable failure, and refuses to enter ready state when zero providers are enabled. This prevents a session with no data providers from being reported as a working telemetry adapter.

### FIM

The native helper now keeps the overlapped event alive for the session, preserves completion bytes under a lock, and lets the polling API consume completed data safely. Native read and completion errors are logged. The Zig watcher refuses to report readiness when all requested directory watchers fail.

### Registry

The Registry monitor now opens native `RegNotifyChangeKeyValue` watchers for the configured HKLM Services and Run locations, polls notification events without blocking the telemetry loop, converts them into the existing `RegEvent` queue, and re-arms each notification. Native startup failure is reported as `NoWatchersStarted` rather than silently passing.

## Required Windows validation order

1. Build the CMake helpers and Zig core from fresh source.
2. Start the daemon elevated only in the isolated test environment.
3. Confirm `wfp=false` or `wfp=true` matches the actual device state; never infer it from compile capabilities.
4. Confirm ETW provider-enable diagnostics and `etw_ready`.
5. Modify a disposable Registry test value under the configured HKLM test key and verify a Registry event reaches the canonical queue.
6. Modify a disposable test file watched by FIM and verify a FIM event reaches the queue.
7. Re-run the synthetic XSS fixture and verify detection, policy, PEP, audit, and forensic counters remain correct.
8. Only after all declared gates pass, run controlled enforcement tests.

The WFP device/driver installation is an environment/deployment prerequisite, not something user-mode source can safely fake.
