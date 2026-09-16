// AEGIS canonical WFP production boundary.
//
// This module defines the runtime contract for Windows filtering. It does not
// open WFP handles or mutate filters directly: the Rust PEP remains the sole
// enforcement authority and owns the native WFP adapter.
const std = @import("std");

pub const EnforcementStatus = enum { accepted, rejected, unavailable };

pub const WfpRequest = struct {
    ipv4: u32,
    rule_id: u32,
    request_id: u64,
};

pub fn submitViaPep(request: WfpRequest) EnforcementStatus {
    _ = request;
    // The concrete FFI call is owned by src/policy/pep_bindings.zig and the
    // aegis_pep.dll boundary. Never fail open when that authority is absent.
    return .unavailable;
}

comptime {
    std.testing.refAllDecls(@This());
}

test "WFP production boundary is fail closed without PEP" {
    try std.testing.expectEqual(EnforcementStatus.unavailable, submitViaPep(.{
        .ipv4 = 0,
        .rule_id = 0,
        .request_id = 0,
    }));
}
