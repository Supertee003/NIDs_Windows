## Issue #30 addendum — ETW consumer teardown stop-line finding

**Date:** 2026-11-08
**Target source commit:** `cf19e135a1c3f50eb7d8ea95f0d6b9b5f6576c98`
**Evidence level:** E1 (static source inspection only)
**Issue:** [#30 heap crash](https://github.com/Supertee003/NIDs_Windows/issues/30)

### Observed flow

`src/windows/etw_native.c` starts `consumer_thread`, which reads shared `g_session` state and runs `OpenTraceW`/`ProcessTrace`. Its stop path calls `StopTrace`, waits on `consumer_thread` for 5 seconds, ignores the wait result, closes the thread handle, and frees `g_session.properties` regardless of whether the worker terminated. The callback also accesses shared callback/context and `ext_buffer` state. Microsoft documents that stopping a real-time ETW controller causes `ProcessTrace` to return after processing buffered events; `CloseTrace` is also an explicit consumer-side way to stop processing and can return `ERROR_CTX_CLOSE_PENDING` while queued events drain ([ProcessTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace), [CloseTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-closetrace)).

`src/windows/etw_realtime.zig` ignores the native stop return code and marks the source stopped unconditionally. This can hide teardown failure from the caller and health reporting. The native start path also calls `InitializeCriticalSection(&g_lock)` on each start but has no matching `DeleteCriticalSection`; a failed consumer-thread creation stops/frees some session resources but leaves stale `session_handle`/`properties` state. These make repeated and partial-start lifecycle ownership unclear.

### Stop-line assessment

If the consumer thread does not terminate within the timeout, the C stop path can release resources while native worker activity may still be in flight. The source inspection does not prove that `ProcessTrace` or its callback dereferences `properties` after the wait, nor that this caused the historical `0xc0000374` crash. Shared session/callback lifetime and ignored join status nevertheless make teardown safety unproven. Treat this as a lifecycle/memory-safety blocker under the project's stop-the-line rules.

### Required resolution gate

Before code changes, define the ETW ownership and stop contract: stop the controller session, close the consumer handle as needed to unblock `ProcessTrace`, wait for confirmed thread termination, and release shared state only after join success. Propagate any failed stop/join to Zig and service health; preserve owned state rather than free it if safe termination cannot be confirmed. Cover start failure, partial initialization, repeated stop, and restart races, including lock initialization. Verify with native helper tests and Windows service cycles under Page Heap/debugger before closing #30. Do not claim this is the root cause without crash-dump evidence.

## Resolution update — ETW-LIFE-001 (2026-11-08)

The E1 hazard was addressed in source commit `adb1b73` and recorded in `ETW-LIFE-001-20261108.md`. Lifecycle locks now have static lifetime and serialize start/stop/callback registration. Stop disables and drains callbacks, stops the controller, closes the consumer trace on controller-stop failure, waits for confirmed worker termination, and only then releases handles/properties. Native failure is surfaced through Zig and ETW worker health. Partial startup cleanup retains state if controller cleanup fails.

Verification: native ETW DLL build PASS; `zig build` PASS; full Zig suite 2058 passed / 10 skipped; ETW contract/session tests 9/9; `zig fmt --check` and `git diff --check` PASS. This is E2 only; no live ETW start/stop or installed-service Page Heap test was performed. After the service was observed STOPPED following verification, a later query showed RUNNING with a new PID. Recovery configuration shows restart-on-failure actions; the unelevated event query did not retrieve matching service events. Issue #30 remains OPEN until this restart/crash is attributed and Windows lifecycle stress evidence passes. This patch is not claimed as the historical crash's root cause.
