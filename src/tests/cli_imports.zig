// REBUILD-003: compile/import coverage for relocated CLI tooling.
comptime {
    _ = @import("cli/cluster_cli.zig");
    _ = @import("cli/etw_realtime_cli.zig");
    _ = @import("cli/federation_bench_cli.zig");
    _ = @import("cli/federation_cli.zig");
    _ = @import("cli/federation_tcp_cli.zig");
    _ = @import("cli/federation_tls_cli.zig");
    _ = @import("cli/host_telemetry_cli.zig");
    _ = @import("cli/host_telemetry_detectors_cli.zig");
    _ = @import("cli/host_telemetry_mock_cli.zig");
    _ = @import("cli/host_telemetry_scenarios_cli.zig");
    _ = @import("cli/injection_detector_cli.zig");
    _ = @import("cli/integration_test_cli.zig");
    _ = @import("cli/ml_test_cli.zig");
    _ = @import("cli/nose_pipe_e2e_cli.zig");
    _ = @import("cli/perf_benchmark_cli.zig");
    _ = @import("cli/registry_trie_cli.zig");
    _ = @import("cli/windows_adapters_cli.zig");
}
test "relocated CLI tools compile" {
    try @import("std").testing.expect(true);
}
