// federation_tls_cli.zig - AEGIS Phase 39 Ext 3: TLS/mTLS Federation CLI.
const std = @import("std");
const tls = @import("federation_tls.zig");
const fc = @import("federation_codec.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    std.debug.print("AEGIS NIDS - Phase 39 Ext 3: TLS/mTLS Federation CLI\n", .{});
    std.debug.print("======================================================\n\n", .{});

    const mode: []const u8 = if (args.len >= 2) args[1] else "help";
    if (std.mem.eql(u8, mode, "help")) { printHelp(); return; }
    if (std.mem.eql(u8, mode, "demo")) { try runDemo(); return; }
    std.debug.print("Unknown mode: {s}\n", .{mode});
    printHelp();
}

fn printHelp() void {
    std.debug.print("Usage:\n  federation_tls_cli help  - this screen\n  federation_tls_cli demo   - run 5 TLS scenarios\n", .{});
}

fn runDemo() !void {
    const results = [_]struct { name: []const u8, ok: bool }{
        .{ .name = "kill-switch-off", .ok = scenarioKillSwitchOff() },
        .{ .name = "cert-validation", .ok = scenarioCertValidation() },
        .{ .name = "tls-roundtrip", .ok = scenarioTlsRoundtrip() },
        .{ .name = "mtls-handshake", .ok = scenarioMtlsHandshake() },
        .{ .name = "framed-over-tls", .ok = scenarioFramedOverTls() },
    };
    var passed: usize = 0;
    for (results) |r| {
        const tag = if (r.ok) "PASS" else "FAIL";
        std.debug.print("  [{s}] {s}\n", .{ tag, r.name });
        if (r.ok) passed += 1;
    }
    std.debug.print("\n{d}/{d} scenarios passed\n", .{ passed, results.len });
    if (passed != results.len) std.process.exit(1);
}

fn scenarioKillSwitchOff() bool {
    var srv = tls.TlsServer.init(.{ .enabled = false });
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch return false;
    const err = srv.bindAndListen(addr, 4);
    const ok = if (err) |_| false else |e| e == error.NotEnabled;
    std.debug.print("  -> kill switch off; bindAndListen returned {s}\n", .{if (ok) "NotEnabled (expected)" else "unexpected"});
    return ok;
}

fn scenarioCertValidation() bool {
    var config = tls.TlsConfig{ .enabled = true };
    tls.setExpectedCn(&config, "aegis-sensor.example.com");
    const validator = tls.CertificateValidator.init(config);
    const cert = validator.loadCertificate("test.pem") catch return false;
    validator.validate(cert, @intCast(std.time.nanoTimestamp())) catch return false;
    std.debug.print("  -> cert CN='{s}'; validation passed\n", .{cert.cnStr()});
    return true;
}

fn scenarioTlsRoundtrip() bool {
    var srv = tls.TlsServer.init(.{ .enabled = true });
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch return false;
    srv.bindAndListen(addr, 4) catch return false;
    const bound = srv.boundAddress();
    const A = struct { srv: *tls.TlsServer, acc: *?tls.TlsTransport, fn run(a: *@This()) void { a.acc.* = a.srv.accept() catch return; } };
    var acc: ?tls.TlsTransport = null;
    var aargs = A{ .srv = &srv, .acc = &acc };
    const thread = std.Thread.spawn(.{}, A.run, .{&aargs}) catch return false;
    var client = tls.TlsTransport.init(.{ .enabled = true });
    defer client.deinit();
    client.connect(bound) catch return false;
    thread.join();
    var server_side = acc orelse return false;
    defer server_side.deinit();
    const payload = "tls-secret-data";
    client.sendBytes(payload) catch return false;
    var buf: [32]u8 = undefined;
    const n = server_side.recvBytes(&buf) catch return false;
    const ok = n == payload.len and std.mem.eql(u8, payload, buf[0..n]);
    std.debug.print("  -> sent {d} bytes via TLS; received {d}; match={}\n", .{ payload.len, n, ok });
    return ok;
}

fn scenarioMtlsHandshake() bool {
    var srv = tls.TlsServer.init(.{ .enabled = true, .require_client_cert = true });
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch return false;
    srv.bindAndListen(addr, 4) catch return false;
    const bound = srv.boundAddress();
    const A = struct { srv: *tls.TlsServer, acc: *?tls.TlsTransport, fn run(a: *@This()) void { a.acc.* = a.srv.accept() catch return; } };
    var acc: ?tls.TlsTransport = null;
    var aargs = A{ .srv = &srv, .acc = &acc };
    const thread = std.Thread.spawn(.{}, A.run, .{&aargs}) catch return false;
    var client = tls.TlsTransport.init(.{ .enabled = true, .require_client_cert = true });
    defer client.deinit();
    client.connect(bound) catch return false;
    thread.join();
    var server_side = acc orelse return false;
    defer server_side.deinit();
    const ok = client.state == .established and server_side.state == .established
        and client.handshake_count == 1 and server_side.handshake_count == 1;
    std.debug.print("  -> mTLS handshake; client_state={s}, server_state={s}\n", .{ client.state.toString(), server_side.state.toString() });
    return ok;
}

fn scenarioFramedOverTls() bool {
    var srv = tls.TlsServer.init(.{ .enabled = true });
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch return false;
    srv.bindAndListen(addr, 4) catch return false;
    const bound = srv.boundAddress();
    const A = struct { srv: *tls.TlsServer, acc: *?tls.TlsTransport, fn run(a: *@This()) void { a.acc.* = a.srv.accept() catch return; } };
    var acc: ?tls.TlsTransport = null;
    var aargs = A{ .srv = &srv, .acc = &acc };
    const thread = std.Thread.spawn(.{}, A.run, .{&aargs}) catch return false;
    var client = tls.TlsTransport.init(.{ .enabled = true });
    defer client.deinit();
    client.connect(bound) catch return false;
    thread.join();
    var server_side = acc orelse return false;
    defer server_side.deinit();
    var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
    const n = fc.encode(.{ .msg_type = .heartbeat, .from_node_id = 42, .timestamp_ns = 1_000_000_000 }, &wire) catch return false;
    client.sendBytes(wire[0..n]) catch return false;
    const tp = server_side.asTransport();
    var buf: [fc.MAX_FRAME_SIZE]u8 = undefined;
    const rn = tp.recv(&buf) catch return false;
    const msg = fc.decode(buf[0..rn]) catch return false;
    const ok = msg.from_node_id == 42;
    std.debug.print("  -> framed heartbeat over TLS; from_node_id={d}\n", .{msg.from_node_id});
    return ok;
}
