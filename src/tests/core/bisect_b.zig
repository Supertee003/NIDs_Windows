// REBUILD-002 bisect part B: spine + proofs + hardening + harness + benchmarks
comptime {
    _ = @import("../../core/bridge_init.zig");
    _ = @import("../../core/nids_main.zig");
    _ = @import("../../core/nids_capture.zig");
    _ = @import("../../core/nids_analyze.zig");
    _ = @import("../proofs/compliance_proof.zig");
    _ = @import("../../core/compliance_reporter.zig");
    _ = @import("../proofs/config_reload_proof.zig");
    _ = @import("../../core/contract_freeze.zig");
    _ = @import("../proofs/documentation_proof.zig");
    _ = @import("../../core/fabric_accounting.zig");
    _ = @import("../proofs/final_integration_proof.zig");
    _ = @import("../proofs/performance_tuning_proof.zig");
    _ = @import("../../core/legacy_removal.zig");
    _ = @import("../../core/canary_progression.zig");
    _ = @import("../../core/concurrency_harden.zig");
    _ = @import("../integration/concurrency_harden_integration.zig");
    _ = @import("../../core/e2e_harness.zig");
    _ = @import("../integration/e2e_harness_integration.zig");
    _ = @import("../../core/integration_test.zig");
    _ = @import("../cli/integration_test_cli.zig");
    _ = @import("../../core/perf_benchmark.zig");
    _ = @import("../cli/perf_benchmark_cli.zig");
    _ = @import("../../core/performance_harness.zig");
    _ = @import("../integration/performance_integration.zig");
}
test "bisectB compiles" {
    try @import("std").testing.expect(true);
}
