//! REBUILD-003: config contract tests for the relocated test configs
//! (configs/test/). The JSON files are surfaced through build options
//! (`core_test_configs`) because @embedFile cannot cross the src/ module
//! root. Each config must parse as JSON and carry the fields the
//! documented operators rely on (kill_switch semantics: everything
//! defaults to detection-only).

const std = @import("std");
const build_configs = @import("core_test_configs");

const host_correlator_config_json = build_configs.host_correlator_config_json;
const integration_test_config_json = build_configs.integration_test_config_json;
const perf_benchmark_config_json = build_configs.perf_benchmark_config_json;

fn expectKillSwitchOff(parsed: std.json.Parsed(std.json.Value)) !void {
    const obj = parsed.value.object;
    const ks = obj.get("kill_switch") orelse return error.MissingKillSwitch;
    const enabled = ks.object.get("enabled") orelse return error.MissingEnabled;
    // Safety invariant: configs ship with kill switch OFF (detection-only).
    try std.testing.expect(enabled == .bool and enabled.bool == false);
}

test "host_correlator_config.json parses with required schema" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, host_correlator_config_json, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    if (obj.get("version") == null) return error.MissingVersion;
    try std.testing.expectEqualStrings("host_telemetry", obj.get("module").?.string);
    // Required correlation + telemetry sections from the documented schema.
    _ = obj.get("sources").?.object.get("process_tracking").?;
    _ = obj.get("sources").?.object.get("file_integrity").?;
    _ = obj.get("sources").?.object.get("registry_watch").?;
    _ = obj.get("correlation").?.object.get("window_ms").?;
    try expectKillSwitchOff(parsed);
}

test "integration_test_config.json parses with required schema" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, integration_test_config_json, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("integration_test", obj.get("module").?.string);
    const scenarios = obj.get("scenarios").?.array;
    // Every documented scenario must be present and named.
    try std.testing.expect(scenarios.items.len >= 6);
    for (scenarios.items) |sc| {
        if (sc.object.get("name") == null) return error.MissingScenarioName;
        if (sc.object.get("description") == null) return error.MissingScenarioDesc;
    }
    try expectKillSwitchOff(parsed);
}

test "perf_benchmark_config.json parses with required schema" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, perf_benchmark_config_json, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("perf_benchmark", obj.get("module").?.string);
    if (obj.get("version") == null) return error.MissingVersion;
    try expectKillSwitchOff(parsed);
}
