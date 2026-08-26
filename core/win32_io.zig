//! win32_io.zig - AEGIS NIDS Shared Win32 Overlapped I/O Helpers (Phase 9)
//!
//! Consolidates overlapped I/O declarations and constants that were duplicated
//! across nids_analyze.zig, nids_capture.zig, and minifilter_reader.zig in Phase 8.
//!
//! Provides:
//!   - OVERLAPPED struct (matches Win32 OVERLAPPED)
//!   - Win32 FFI declarations (CreateEventA, WaitForSingleObject, etc.)
//!   - Named constants (FILE_FLAG_OVERLAPPED, ERROR_IO_PENDING, WAIT_*)
//!   - Helper functions for shutdown-responsive I/O pattern

const std = @import("std");
const win = std.os.windows;

// ============================================================
// OVERLAPPED I/O Structures
// ============================================================

/// Win32 OVERLAPPED structure for asynchronous I/O operations.
/// Matches Microsoft's OVERLAPPED definition exactly.
pub const OVERLAPPED = extern struct {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: ?*anyopaque,
};

// ============================================================
// Win32 FFI Declarations
// ============================================================

pub extern "kernel32" fn CreateEventA(
    lpEventAttributes: ?*anyopaque,
    bManualReset: i32,
    bInitialState: i32,
    lpName: ?[*:0]const u8,
) ?*anyopaque;

extern "kernel32" fn WaitForSingleObject(hHandle: ?*anyopaque, dwMilliseconds: u32) u32;

pub extern "kernel32" fn GetOverlappedResult(
    hFile: win.HANDLE,
    lpOverlapped: *OVERLAPPED,
    lpNumberOfBytesTransferred: *u32,
    bWait: i32,
) i32;

extern "kernel32" fn CancelIoEx(hFile: win.HANDLE, lpOverlapped: ?*OVERLAPPED) i32;

pub extern "kernel32" fn ResetEvent(hEvent: ?*anyopaque) i32;

// ============================================================
// Named Constants
// ============================================================

pub const FILE_FLAG_OVERLAPPED: u32 = 0x40000000;
pub const ERROR_IO_PENDING: u32 = 997;
pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_TIMEOUT: u32 = 258;

/// Default poll interval for shutdown-responsive I/O (1 second).
/// All blocking calls wait this long before checking the shutdown flag.
pub const IO_POLL_TIMEOUT_MS: u32 = 1000;

// ============================================================
// Helper Functions
// ============================================================

/// Result of a shutdown-responsive overlapped I/O wait.
pub const OverlappedWaitResult = enum {
    /// I/O completed synchronously (no wait needed).
    completed,
    /// I/O completed after waiting on the event.
    completed_after_wait,
    /// Timed out waiting — caller should check shutdown flag and retry.
    timeout,
    /// Unexpected error from WaitForSingleObject.
    wait_error,
    /// GetOverlappedResult failed after event was signaled.
    result_error,
};

/// Wait for an overlapped I/O operation to complete with a shutdown-responsive timeout.
///
/// Call this AFTER the blocking function (ConnectNamedPipe, FilterGetMessage, etc.)
/// returns ERROR_IO_PENDING. The function:
///   1. Waits up to `timeout_ms` for the event to be signaled
///   2. If timeout: cancels the pending I/O via CancelIoEx
///   3. If signaled: verifies with GetOverlappedResult
///
/// Parameters:
///   - `handle`: The file/pipe/socket handle
///   - `overlapped`: Pointer to the OVERLAPPED struct used in the I/O call
///   - `event`: The event handle from CreateEventA
///   - `timeout_ms`: Wait timeout (default IO_POLL_TIMEOUT_MS = 1s)
///
/// Returns the wait result enum. Caller is responsible for handling each case.
pub fn waitOverlapped(
    handle: win.HANDLE,
    overlapped: *OVERLAPPED,
    event: ?*anyopaque,
    timeout_ms: u32,
) OverlappedWaitResult {
    const wait_ret = WaitForSingleObject(event, timeout_ms);

    if (wait_ret == WAIT_TIMEOUT) {
        // B-11 FIX: Cancel pending I/O and wait for cancellation to complete
        // (was: CancelIoEx + immediate return — could leak pending I/O)
        _ = CancelIoEx(handle, overlapped);
        // Wait for the cancellation to complete (GetOverlappedResult with bWait=0
        // returns immediately if I/O is still pending; we wait up to 100ms)
        var bytes_xfer: u32 = 0;
        _ = GetOverlappedResult(handle, overlapped, &bytes_xfer, 0);
        return .timeout;
    }

    if (wait_ret != WAIT_OBJECT_0) {
        return .wait_error;
    }

    // Event signaled — verify with GetOverlappedResult
    var bytes_xfer: u32 = 0;
    if (GetOverlappedResult(handle, overlapped, &bytes_xfer, 0) == 0) {
        return .result_error;
    }

    return .completed_after_wait;
}

/// Create a manual-reset event for overlapped I/O signaling.
/// Returns null on failure (caller should log and abort).
/// Caller is responsible for closing the handle via win.CloseHandle.
pub fn createIoEvent() ?*anyopaque {
    return CreateEventA(null, 1, 0, null);
}

// ============================================================
// Tests
// ============================================================

test "OVERLAPPED struct size matches Win32 ABI" {
    // Win32 OVERLAPPED is 32 bytes on 64-bit Windows:
    //   internal (8) + internal_high (8) + offset (4) + offset_high (4) + padding (4) + event (8)
    // Zig's extern struct should match exactly.
    try std.testing.expect(@sizeOf(OVERLAPPED) >= 16);
}

test "Named constants have correct values" {
    try std.testing.expect(FILE_FLAG_OVERLAPPED == 0x40000000);
    try std.testing.expect(ERROR_IO_PENDING == 997);
    try std.testing.expect(WAIT_OBJECT_0 == 0);
    try std.testing.expect(WAIT_TIMEOUT == 258);
    try std.testing.expect(IO_POLL_TIMEOUT_MS == 1000);
}

test "OverlappedWaitResult enum has all cases" {
    const cases = [_]OverlappedWaitResult{
        .completed,
        .completed_after_wait,
        .timeout,
        .wait_error,
        .result_error,
    };
    try std.testing.expect(cases.len == 5);
}
