"""Static contract pins for ETW native-helper lifecycle ownership.

These checks do not substitute for Windows ETW runtime/Page Heap evidence.
"""
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
NATIVE = (REPO / "src/windows/etw_native.c").read_text(encoding="utf-8")
ZIG = (REPO / "src/windows/etw_realtime.zig").read_text(encoding="utf-8")
TELEMETRY = (REPO / "src/pipeline/telemetry_threads.zig").read_text(encoding="utf-8")


def test_callback_lock_has_static_lifetime_across_restarts():
    assert "static SRWLOCK g_lock = SRWLOCK_INIT;" in NATIVE
    assert "InitializeCriticalSection(&g_lock)" not in NATIVE


def test_stop_disables_callback_and_serializes_lifecycle():
    assert "static SRWLOCK g_lifecycle_lock = SRWLOCK_INIT;" in NATIVE
    stop = NATIVE[NATIVE.index("static int aegis_etw_stop_impl"):]
    stop = stop[:stop.index("int aegis_etw_set_callback")]
    assert stop.index("g_session.callback = NULL") < stop.index("ControlTraceW(")
    assert "AcquireSRWLockExclusive(&g_lifecycle_lock)" in stop
    assert "ReleaseSRWLockExclusive(&g_lifecycle_lock)" in stop
    assert "CreateEventW(NULL, TRUE, FALSE, NULL)" in NATIVE
    assert "ERROR_CTX_CLOSE_PENDING" in stop
    assert "CloseTrace((PROCESSTRACE_HANDLE)trace_value)" in stop


def test_stop_joins_consumer_before_closing_or_freeing_resources():
    stop = NATIVE[NATIVE.index("static int aegis_etw_stop_impl"):]
    stop = stop[:stop.index("int aegis_etw_set_callback")]
    wait_at = stop.index("WaitForSingleObject(g_session.consumer_thread, INFINITE)")
    assert wait_at < stop.index("CloseHandle(g_session.consumer_thread)")
    assert wait_at < stop.index("free(g_session.properties)")
    assert "wait_result != WAIT_OBJECT_0" in stop


def test_zig_and_worker_surface_native_stop_failure():
    assert "pub fn stop(self: *EtwSource) !void" in ZIG
    assert "if (rc != 0) {" in ZIG
    assert "return error.EtwStopFailed;" in ZIG
    assert "ETW stop failed" in TELEMETRY
    assert "state.markWorkerFailure(.etw)" in TELEMETRY
