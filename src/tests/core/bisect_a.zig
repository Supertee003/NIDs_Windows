// REBUILD-002 bisect part A: infra + fabric + brain + security models
comptime {
    _ = @import("../../core/diagnostics.zig");
    _ = @import("../../core/memory_pool.zig");
    _ = @import("../../core/priority_queue.zig");
    _ = @import("../../core/brain_engine.zig");
    _ = @import("../integration/brain_integration.zig");
    _ = @import("../proofs/brain_proof.zig");
    _ = @import("../../core/rust_pep.zig");
    _ = @import("../integration/rust_pep_integration.zig");
    _ = @import("../../core/real_ips_path.zig");
    _ = @import("../../core/authority_review.zig");
}
test "bisectA compiles" {
    try @import("std").testing.expect(true);
}
