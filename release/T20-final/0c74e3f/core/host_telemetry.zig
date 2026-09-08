//! host_telemetry.zig - AEGIS NIDS Phase 37: HIDS/XDR Endpoint Correlation
//!
//! Host Intrusion Detection + Extended Detection & Response endpoint layer.
//! Joins host telemetry (process / file / registry / socket) with network
//! flow verdicts to attribute malicious traffic to a responsible process
//! and surface persistence / injection / integrity anomalies.
//!
//! Design principles (mirrors Phase 32 Npcap + Phase 36 ML detector):
//!   - Pure Zig, host-testable on Linux (no Windows API calls in this module)
//!   - Additive only - enforcement stays in WFP kernel driver
//!   - Kill switch OFF by default; consumers opt in via HostConfig{.enabled=true}
//!   - Singleton facade (init/shutdown/instance/isAvailable) - project style
//!   - All host telemetry sources feed a single ingestEvent() entry point;
//!     ETW / FIM / RegistryNotify adapters are external to this module.
//!
//! Correlation model:
//!   1. ProcessTracker: PID -> ProcessInfo (parent chain up to 4 gens)
//!   2. FileIntegrityStore: path -> baseline (sha256 + mtime + size + attrs)
//!   3. RegistryWatchQueue: subscribed keys -> pending changes (ring buffer)
//!   4. SocketTable: PID -> open sockets (local_ip:port, remote_ip:port, proto)
//!   5. CorrelationEngine: when a network flow verdict arrives (from ML
//!      detector) the engine walks SocketTable to find the owning PID,
//!      walks ProcessTracker to compose image/cmdline/parent chain, and
//!      emits a CorrelatedIncident (network + host attribution).
//!
//! Build:
//!   zig test host_telemetry.zig -lc
//!   zig build-exe host_telemetry_cli.zig -lc   (uses this module)
//!
//! Integration:
//!   const ht = @import("host_telemetry.zig");
//!   try ht.HostTelemetry.instance().?.init(allocator, .{});
//!   defer ht.HostTelemetry.instance().?.shutdown();
//!   ht.HostTelemetry.instance().?.ingestEvent(ev);

const std = @import("std");
const crypto = std.crypto.hash.sha2.Sha256;

// ============================================================
// Constants & limits (bounded memory, fixed caps)
// ============================================================

pub const MAX_PROCESSES: usize = 4096;
pub const MAX_IMAGE_PATH: usize = 260;
pub const MAX_CMDLINE: usize = 512;
pub const MAX_USER_SID: usize = 64;
pub const MAX_SIGNER: usize = 64;
pub const MAX_REG_KEY: usize = 256;
pub const MAX_REG_VALUE_NAME: usize = 64;
pub const MAX_FILE_PATH: usize = 320;
pub const MAX_REASONS: usize = 6;
pub const MAX_INCIDENTS: usize = 256;
pub const MAX_SOCKETS_PER_PID: usize = 32;
pub const PARENT_CHAIN_DEPTH: usize = 4;
pub const CORRELATION_WINDOW_MS: i64 = 5_000; // +-5s slide for network+host join

// Hashes
pub const SHA256_LEN: usize = 32;

// ============================================================
// Configuration (kill switch + per-source enables)
// ============================================================

pub const HostConfig = struct {
    /// Master kill switch. OFF by default - host telemetry ingestion is a
    /// no-op until explicitly enabled by the runtime. Enforcement stays in
    /// the WFP driver; this module is detection-only (additive).
    enabled: bool = false,
    /// Per-source enables (kept independent so partial rollouts are safe)
    enable_process_tracking: bool = true,
    enable_file_integrity: bool = true,
    enable_registry_watch: bool = true,
    enable_socket_correlation: bool = true,
    /// Incident aggregation
    correlation_window_ms: i64 = CORRELATION_WINDOW_MS,
    max_incidents: usize = MAX_INCIDENTS,
    max_processes: usize = MAX_PROCESSES,
    /// Suspicion thresholds
    parent_chain_depth: u8 = PARENT_CHAIN_DEPTH,
    /// Emit incident when ML verdict score crosses this threshold
    incident_score_threshold: f32 = 0.70,
    // Critical file paths (substring match) - integrity mismatch -> CRITICAL.
    // Default list mirrors Windows system32 + boot-critical locations.
    // (Future: configure via JSON when adapters wire in.)
};

// ============================================================
// Enums
// ============================================================

pub const ProcessIntegrity = enum(u8) {
    low = 0,
    medium = 1,
    high = 2,
    system = 3,

    pub fn toString(self: ProcessIntegrity) []const u8 {
        return switch (self) {
            .low => "LOW",
            .medium => "MEDIUM",
            .high => "HIGH",
            .system => "SYSTEM",
        };
    }

    pub fn isElevated(self: ProcessIntegrity) bool {
        return self == .high or self == .system;
    }
};

pub const HostEventType = enum(u8) {
    process_create = 0,
    process_exit = 1,
    image_load = 2,
    file_create = 3,
    file_modify = 4,
    file_delete = 5,
    registry_set_value = 6,
    registry_create_key = 7,
    registry_delete_key = 8,
    socket_open = 9,
    socket_close = 10,

    pub fn toString(self: HostEventType) []const u8 {
        return switch (self) {
            .process_create => "PROCESS_CREATE",
            .process_exit => "PROCESS_EXIT",
            .image_load => "IMAGE_LOAD",
            .file_create => "FILE_CREATE",
            .file_modify => "FILE_MODIFY",
            .file_delete => "FILE_DELETE",
            .registry_set_value => "REG_SET_VALUE",
            .registry_create_key => "REG_CREATE_KEY",
            .registry_delete_key => "REG_DELETE_KEY",
            .socket_open => "SOCKET_OPEN",
            .socket_close => "SOCKET_CLOSE",
        };
    }

    pub fn isCritical(self: HostEventType) bool {
        return switch (self) {
            .file_modify, .file_delete, .registry_set_value, .registry_create_key => true,
            else => false,
        };
    }
};

pub const SocketProto = enum(u8) {
    tcp = 6,
    udp = 17,

    pub fn toString(self: SocketProto) []const u8 {
        return switch (self) {
            .tcp => "TCP",
            .udp => "UDP",
        };
    }
};

pub const SuspicionReason = enum(u8) {
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

    pub fn toString(self: SuspicionReason) []const u8 {
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
        };
    }

    pub fn isCritical(self: SuspicionReason) bool {
        return switch (self) {
            .file_integrity_mismatch,
            .file_integrity_deleted,
            .registry_persistence_key,
            .registry_critical_key,
            .network_host_correlation,
            .integrity_escalation,
            => true,
            else => false,
        };
    }
};

pub const IncidentSeverity = enum(u8) {
    info = 0,
    low = 1,
    medium = 2,
    high = 3,
    critical = 4,

    pub fn toString(self: IncidentSeverity) []const u8 {
        return switch (self) {
            .info => "INFO",
            .low => "LOW",
            .medium => "MEDIUM",
            .high => "HIGH",
            .critical => "CRITICAL",
        };
    }
};

// ============================================================
// HostEvent (unified record ingested from all sources)
// ============================================================

pub const HostEvent = struct {
    timestamp_ns: i64 = 0,
    event_type: HostEventType,
    pid: u32 = 0,
    ppid: u32 = 0,
    image_path: [MAX_IMAGE_PATH]u8 = [_]u8{0} ** MAX_IMAGE_PATH,
    image_path_len: u16 = 0,
    cmdline: [MAX_CMDLINE]u8 = [_]u8{0} ** MAX_CMDLINE,
    cmdline_len: u16 = 0,
    user_sid: [MAX_USER_SID]u8 = [_]u8{0} ** MAX_USER_SID,
    user_sid_len: u8 = 0,
    integrity: ProcessIntegrity = .medium,
    signer: [MAX_SIGNER]u8 = [_]u8{0} ** MAX_SIGNER,
    signer_len: u8 = 0,
    is_signed: bool = false,
    // File-specific
    file_path: [MAX_FILE_PATH]u8 = [_]u8{0} ** MAX_FILE_PATH,
    file_path_len: u16 = 0,
    file_hash: [SHA256_LEN]u8 = [_]u8{0} ** SHA256_LEN,
    file_size: u64 = 0,
    file_attrs: u32 = 0,
    // Registry-specific
    reg_key: [MAX_REG_KEY]u8 = [_]u8{0} ** MAX_REG_KEY,
    reg_key_len: u16 = 0,
    reg_value_name: [MAX_REG_VALUE_NAME]u8 = [_]u8{0} ** MAX_REG_VALUE_NAME,
    reg_value_name_len: u8 = 0,
    // Socket-specific
    proto: SocketProto = .tcp,
    local_ip: [4]u8 = .{ 0, 0, 0, 0 },
    local_port: u16 = 0,
    remote_ip: [4]u8 = .{ 0, 0, 0, 0 },
    remote_port: u16 = 0,

    pub fn imagePath(self: *const HostEvent) []const u8 {
        return self.image_path[0..self.image_path_len];
    }
    pub fn commandLine(self: *const HostEvent) []const u8 {
        return self.cmdline[0..self.cmdline_len];
    }
    pub fn filePath(self: *const HostEvent) []const u8 {
        return self.file_path[0..self.file_path_len];
    }
    pub fn regKey(self: *const HostEvent) []const u8 {
        return self.reg_key[0..self.reg_key_len];
    }
    pub fn regValueName(self: *const HostEvent) []const u8 {
        return self.reg_value_name[0..self.reg_value_name_len];
    }
    pub fn signerName(self: *const HostEvent) []const u8 {
        return self.signer[0..self.signer_len];
    }
};

// ============================================================
// ProcessTracker (PID -> ProcessInfo, parent chain walking)
// ============================================================

pub const ProcessInfo = struct {
    pid: u32 = 0,
    ppid: u32 = 0,
    image_path: [MAX_IMAGE_PATH]u8 = [_]u8{0} ** MAX_IMAGE_PATH,
    image_path_len: u16 = 0,
    cmdline: [MAX_CMDLINE]u8 = [_]u8{0} ** MAX_CMDLINE,
    cmdline_len: u16 = 0,
    integrity: ProcessIntegrity = .medium,
    is_signed: bool = false,
    created_ns: i64 = 0,
    exited_ns: i64 = 0,
    alive: bool = false,
    suspicious_flags: u32 = 0,

    pub fn imagePath(self: *const ProcessInfo) []const u8 {
        return self.image_path[0..self.image_path_len];
    }
    pub fn commandLine(self: *const ProcessInfo) []const u8 {
        return self.cmdline[0..self.cmdline_len];
    }
    pub fn isSuspicious(self: *const ProcessInfo) bool {
        return self.suspicious_flags != 0;
    }
};

pub const ProcessTracker = struct {
    allocator: std.mem.Allocator,
    procs: std.AutoHashMap(u32, ProcessInfo),
    max_processes: usize,
    total_create: u64 = 0,
    total_exit: u64 = 0,
    total_suspicious: u64 = 0,
    suspicious_parent_pairs: u64 = 0,
    integrity_escalations: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, max_processes: usize) ProcessTracker {
        return .{
            .allocator = allocator,
            .procs = std.AutoHashMap(u32, ProcessInfo).init(allocator),
            .max_processes = max_processes,
        };
    }

    pub fn deinit(self: *ProcessTracker) void {
        self.procs.deinit();
    }

    /// Track a process create event; returns suspicion reason (none if clean).
    /// Detection rules:
    ///   - Parent-child anomaly: parent image contains known suspicious token
    ///     (e.g. word/excel spawning cmd/powershell) - classic macro attack
    ///   - Integrity escalation: parent integrity < child integrity (e.g.
    ///     LOW process spawning HIGH/SYSTEM child via UAC bypass)
    ///   - Unsigned elevated: HIGH/SYSTEM integrity but is_signed=false
    pub fn trackCreate(self: *ProcessTracker, ev: HostEvent) SuspicionReason {
        if (self.procs.count() >= self.max_processes) {
            // Evict oldest exited entry (LRU-ish; avoids unbounded growth).
            self.evictOneExited();
        }

        var pi = ProcessInfo{
            .pid = ev.pid,
            .ppid = ev.ppid,
            .integrity = ev.integrity,
            .is_signed = ev.is_signed,
            .created_ns = ev.timestamp_ns,
            .alive = true,
        };
        const img = ev.imagePath();
        @memcpy(pi.image_path[0..img.len], img);
        pi.image_path_len = @intCast(img.len);
        const cl = ev.commandLine();
        @memcpy(pi.cmdline[0..cl.len], cl);
        pi.cmdline_len = @intCast(cl.len);

        var reason: SuspicionReason = .none;

        // Parent-child anomaly check
        if (self.procs.get(ev.ppid)) |parent| {
            if (isSuspiciousParentChild(parent.imagePath(), pi.imagePath())) {
                pi.suspicious_flags |= 1;
                reason = .parent_child_anomaly;
                self.suspicious_parent_pairs += 1;
            }
            // Integrity escalation
            if (@intFromEnum(parent.integrity) < @intFromEnum(pi.integrity)) {
                pi.suspicious_flags |= 2;
                if (reason == .none) reason = .integrity_escalation;
                self.integrity_escalations += 1;
            }
        }

        // Unsigned elevated check (parentless processes still get this check)
        if (ev.is_signed == false and pi.integrity.isElevated()) {
            pi.suspicious_flags |= 4;
            if (reason == .none) reason = .unsigned_elevated;
            // Suspicious system path: image lives under system32 but unsigned
            if (isInSystemPath(pi.imagePath())) {
                reason = .unsigned_system_path;
            }
        }

        self.procs.put(ev.pid, pi) catch {};
        self.total_create += 1;
        if (reason != .none) self.total_suspicious += 1;
        return reason;
    }

    pub fn trackExit(self: *ProcessTracker, pid: u32, timestamp_ns: i64) void {
        if (self.procs.getPtr(pid)) |pi| {
            pi.alive = false;
            pi.exited_ns = timestamp_ns;
            self.total_exit += 1;
        }
    }

    pub fn getProcess(self: *const ProcessTracker, pid: u32) ?ProcessInfo {
        return self.procs.get(pid);
    }

    /// Walk parent chain up to `depth` generations; returns count actually
    /// resolved (0 if pid unknown, 1 if no parent tracked).
    pub fn parentChain(self: *const ProcessTracker, pid: u32, depth: u8, out: []ProcessInfo) usize {
        var n: usize = 0;
        var cur = pid;
        var i: u8 = 0;
        while (i < depth) : (i += 1) {
            const p = self.procs.get(cur) orelse break;
            if (n < out.len) {
                out[n] = p;
                n += 1;
            }
            if (p.ppid == 0 or p.ppid == cur) break;
            cur = p.ppid;
        }
        return n;
    }

    pub fn aliveCount(self: *const ProcessTracker) usize {
        var c: usize = 0;
        var it = self.procs.valueIterator();
        while (it.next()) |p| {
            if (p.alive) c += 1;
        }
        return c;
    }

    pub fn count(self: *const ProcessTracker) usize {
        return self.procs.count();
    }

    fn evictOneExited(self: *ProcessTracker) void {
        var it = self.procs.iterator();
        var victim: ?u32 = null;
        while (it.next()) |entry| {
            if (!entry.value_ptr.alive) {
                victim = entry.key_ptr.*;
                break;
            }
        }
        if (victim) |v| {
            _ = self.procs.remove(v);
        } else if (self.procs.count() > 0) {
            // No exited entries - evict oldest alive (avoid infinite growth)
            var oldest_ns: i64 = std.math.maxInt(i64);
            var oldest_pid: u32 = 0;
            it = self.procs.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.created_ns < oldest_ns) {
                    oldest_ns = entry.value_ptr.created_ns;
                    oldest_pid = entry.key_ptr.*;
                }
            }
            _ = self.procs.remove(oldest_pid);
        }
    }

    pub fn resetStats(self: *ProcessTracker) void {
        self.total_create = 0;
        self.total_exit = 0;
        self.total_suspicious = 0;
        self.suspicious_parent_pairs = 0;
        self.integrity_escalations = 0;
    }
};

/// Classic macro / phishing attack pattern: office app spawns shell.
pub fn isSuspiciousParentChild(parent_img: []const u8, child_img: []const u8) bool {
    const parents = [_][]const u8{
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "msaccess.exe", "visio.exe",
    };
    const children = [_][]const u8{
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
        "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    };
    var parent_buf: [MAX_IMAGE_PATH]u8 = undefined;
    var child_buf: [MAX_IMAGE_PATH]u8 = undefined;
    const pl = toLowerBuf(parent_img, &parent_buf);
    const cl = toLowerBuf(child_img, &child_buf);
    const parent_lower = parent_buf[0..pl];
    const child_lower = child_buf[0..cl];

    for (parents) |p| {
        if (std.mem.endsWith(u8, parent_lower, p)) {
            for (children) |c| {
                if (std.mem.endsWith(u8, child_lower, c)) return true;
            }
        }
    }
    return false;
}

pub fn isInSystemPath(img: []const u8) bool {
    var buf: [MAX_IMAGE_PATH]u8 = undefined;
    const n = toLowerBuf(img, &buf);
    const lower = buf[0..n];
    return std.mem.indexOf(u8, lower, "\\system32\\") != null or
        std.mem.indexOf(u8, lower, "\\syswow64\\") != null or
        std.mem.indexOf(u8, lower, "\\windows\\") != null;
}

fn toLowerBuf(src: []const u8, dst: anytype) usize {
    const cap = dst.len;
    const n = @min(src.len, cap);
    var i: usize = 0;
    while (i < n) : (i += 1) dst[i] = std.ascii.toLower(src[i]);
    return n;
}

// ============================================================
// FileIntegrityStore (path -> baseline; detects mismatch/delete/new)
// ============================================================

pub const FileBaseline = struct {
    hash: [SHA256_LEN]u8 = [_]u8{0} ** SHA256_LEN,
    size: u64 = 0,
    mtime_ns: i64 = 0,
    attrs: u32 = 0,
    set_ns: i64 = 0,
};

pub const FileChangeKind = enum(u8) {
    none = 0,
    created = 1,
    modified = 2,
    deleted = 3,
    attrs_changed = 4,

    pub fn toString(self: FileChangeKind) []const u8 {
        return switch (self) {
            .none => "NONE",
            .created => "CREATED",
            .modified => "MODIFIED",
            .deleted => "DELETED",
            .attrs_changed => "ATTRS_CHANGED",
        };
    }
};

pub const FileChange = struct {
    kind: FileChangeKind,
    path: [MAX_FILE_PATH]u8 = [_]u8{0} ** MAX_FILE_PATH,
    path_len: u16 = 0,
    old_hash: [SHA256_LEN]u8 = [_]u8{0} ** SHA256_LEN,
    new_hash: [SHA256_LEN]u8 = [_]u8{0} ** SHA256_LEN,
    pid: u32 = 0,
    timestamp_ns: i64 = 0,

    pub fn pathStr(self: *const FileChange) []const u8 {
        return self.path[0..self.path_len];
    }
};

pub const FileIntegrityStore = struct {
    allocator: std.mem.Allocator,
    baselines: std.StringHashMap(FileBaseline),
    // path key storage (owned) - StringHashMap holds []const u8 keys
    path_arena: std.heap.ArenaAllocator,
    total_baselined: u64 = 0,
    total_mismatch: u64 = 0,
    total_deleted: u64 = 0,
    total_created: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) FileIntegrityStore {
        return .{
            .allocator = allocator,
            .baselines = std.StringHashMap(FileBaseline).init(allocator),
            .path_arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *FileIntegrityStore) void {
        self.baselines.deinit();
        self.path_arena.deinit();
    }

    /// Establish a baseline for a path. Subsequent observe() calls compare
    /// against this snapshot.
    pub fn setBaseline(self: *FileIntegrityStore, path: []const u8, hash: [SHA256_LEN]u8, size: u64, mtime_ns: i64, attrs: u32, now_ns: i64) !void {
        const key = try self.path_arena.allocator().dupe(u8, path);
        const bl = FileBaseline{
            .hash = hash,
            .size = size,
            .mtime_ns = mtime_ns,
            .attrs = attrs,
            .set_ns = now_ns,
        };
        try self.baselines.put(key, bl);
        self.total_baselined += 1;
    }

    /// Observe a file event and compare to baseline. Returns change kind
    /// (none if matching baseline, modified/deleted/created/attrs_changed).
    pub fn observe(self: *FileIntegrityStore, path: []const u8, hash: [SHA256_LEN]u8, size: u64, mtime_ns: i64, attrs: u32, event_type: HostEventType, now_ns: i64) FileChangeKind {
        _ = now_ns;
        const bl = self.baselines.get(path);
        if (event_type == .file_delete) {
            if (bl != null) {
                self.total_deleted += 1;
                return .deleted;
            }
            return .none;
        }
        if (bl) |baseline| {
            if (!std.mem.eql(u8, &baseline.hash, &hash)) {
                self.total_mismatch += 1;
                return .modified;
            }
            if (baseline.attrs != attrs) return .attrs_changed;
            if (baseline.size != size) {
                self.total_mismatch += 1;
                return .modified;
            }
            if (baseline.mtime_ns != mtime_ns) return .none; // mtime-only change with matching hash/size = benign
            return .none;
        }
        // No baseline - new file
        self.total_created += 1;
        return .created;
    }

    pub fn getBaseline(self: *const FileIntegrityStore, path: []const u8) ?FileBaseline {
        return self.baselines.get(path);
    }

    pub fn baselineCount(self: *const FileIntegrityStore) usize {
        return self.baselines.count();
    }

    pub fn resetStats(self: *FileIntegrityStore) void {
        self.total_baselined = 0;
        self.total_mismatch = 0;
        self.total_deleted = 0;
        self.total_created = 0;
    }
};

/// Compute SHA-256 of arbitrary data (used by FIM adapter to hash file bytes).
pub fn sha256(data: []const u8) [SHA256_LEN]u8 {
    var h: [SHA256_LEN]u8 = undefined;
    crypto.hash(data, &h, .{});
    return h;
}

// ============================================================
// RegistryWatchQueue (subscribed keys; pending changes ring buffer)
// ============================================================

pub const RegistryChange = struct {
    timestamp_ns: i64 = 0,
    event_type: HostEventType,
    key: [MAX_REG_KEY]u8 = [_]u8{0} ** MAX_REG_KEY,
    key_len: u16 = 0,
    value_name: [MAX_REG_VALUE_NAME]u8 = [_]u8{0} ** MAX_REG_VALUE_NAME,
    value_name_len: u8 = 0,
    pid: u32 = 0,

    pub fn keyStr(self: *const RegistryChange) []const u8 {
        return self.key[0..self.key_len];
    }
    pub fn valueNameStr(self: *const RegistryChange) []const u8 {
        return self.value_name[0..self.value_name_len];
    }
};

pub const RegistryWatchQueue = struct {
    pending: [64]RegistryChange = undefined,
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,
    persistence_keys: [32][MAX_REG_KEY]u8 = undefined,
    persistence_keys_len: [32]u16 = [_]u16{0} ** 32,
    persistence_keys_count: usize = 0,
    critical_keys: [32][MAX_REG_KEY]u8 = undefined,
    critical_keys_len: [32]u16 = [_]u16{0} ** 32,
    critical_keys_count: usize = 0,
    total_changes: u64 = 0,
    total_persistence_hits: u64 = 0,
    total_critical_hits: u64 = 0,

    pub fn init() RegistryWatchQueue {
        var q = RegistryWatchQueue{};
        q.installDefaultKeyLists();
        return q;
    }

    /// Default persistence locations - matches MITRE ATT&CK T1547 / T1060.
    pub fn installDefaultKeyLists(self: *RegistryWatchQueue) void {
        // Persistence keys (auto-run on logon/boot)
        const persistence = [_][]const u8{
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "\\REGISTRY\\USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "\\REGISTRY\\USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
            "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services",
        };
        for (persistence) |k| self.addPersistenceKey(k);

        // Critical keys (security config - changes are HIGH severity)
        const critical = [_][]const u8{
            "\\REGISTRY\\MACHINE\\SAM\\SAM",
            "\\REGISTRY\\MACHINE\\SECURITY",
            "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        };
        for (critical) |k| self.addCriticalKey(k);
    }

    pub fn addPersistenceKey(self: *RegistryWatchQueue, key: []const u8) void {
        if (self.persistence_keys_count >= 32) return;
        const n = @min(key.len, MAX_REG_KEY);
        const slot = &self.persistence_keys[self.persistence_keys_count];
        @memcpy(slot[0..n], key[0..n]);
        self.persistence_keys_len[self.persistence_keys_count] = @intCast(n);
        self.persistence_keys_count += 1;
    }

    pub fn addCriticalKey(self: *RegistryWatchQueue, key: []const u8) void {
        if (self.critical_keys_count >= 32) return;
        const n = @min(key.len, MAX_REG_KEY);
        const slot = &self.critical_keys[self.critical_keys_count];
        @memcpy(slot[0..n], key[0..n]);
        self.critical_keys_len[self.critical_keys_count] = @intCast(n);
        self.critical_keys_count += 1;
    }

    pub fn enqueue(self: *RegistryWatchQueue, ev: HostEvent) ?SuspicionReason {
        if (self.count >= 64) {
            // Ring buffer overwrite - drop oldest
            self.head = (self.head + 1) % 64;
            self.count -= 1;
        }
        var rc = RegistryChange{
            .timestamp_ns = ev.timestamp_ns,
            .event_type = ev.event_type,
            .pid = ev.pid,
        };
        const k = ev.regKey();
        @memcpy(rc.key[0..k.len], k);
        rc.key_len = @intCast(k.len);
        const vn = ev.regValueName();
        @memcpy(rc.value_name[0..vn.len], vn);
        rc.value_name_len = @intCast(vn.len);

        self.pending[self.tail] = rc;
        self.tail = (self.tail + 1) % 64;
        self.count += 1;
        self.total_changes += 1;

        // Classify
        var reason: SuspicionReason = .none;
        if (self.matchKey(k, .persistence)) {
            reason = .registry_persistence_key;
            self.total_persistence_hits += 1;
        } else if (self.matchKey(k, .critical)) {
            reason = .registry_critical_key;
            self.total_critical_hits += 1;
        }
        return reason;
    }

    pub fn drain(self: *RegistryWatchQueue, out: []RegistryChange) usize {
        const n = @min(self.count, out.len);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            out[i] = self.pending[self.head];
            self.head = (self.head + 1) % 64;
        }
        self.count -= n;
        return n;
    }

    const KeyClass = enum { persistence, critical };

    fn matchKey(self: *const RegistryWatchQueue, key: []const u8, class: KeyClass) bool {
        const list = switch (class) {
            .persistence => self.persistence_keys[0..self.persistence_keys_count],
            .critical => self.critical_keys[0..self.critical_keys_count],
        };
        const lens = switch (class) {
            .persistence => self.persistence_keys_len[0..self.persistence_keys_count],
            .critical => self.critical_keys_len[0..self.critical_keys_count],
        };
        var buf: [MAX_REG_KEY]u8 = undefined;
        const kl = toLowerBuf(key, &buf);
        const key_lower = buf[0..kl];
        for (list, lens) |k, len| {
            const entry = k[0..len];
            var eb: [MAX_REG_KEY]u8 = undefined;
            const el = toLowerBuf(entry, &eb);
            const entry_lower = eb[0..el];
            if (std.mem.startsWith(u8, key_lower, entry_lower)) return true;
        }
        return false;
    }

    pub fn resetStats(self: *RegistryWatchQueue) void {
        self.total_changes = 0;
        self.total_persistence_hits = 0;
        self.total_critical_hits = 0;
    }
};

// ============================================================
// SocketTable (PID -> open sockets; correlation key for network flows)
// ============================================================

pub const SocketEntry = struct {
    pid: u32 = 0,
    proto: SocketProto = .tcp,
    local_ip: [4]u8 = .{ 0, 0, 0, 0 },
    local_port: u16 = 0,
    remote_ip: [4]u8 = .{ 0, 0, 0, 0 },
    remote_port: u16 = 0,
    opened_ns: i64 = 0,
    closed: bool = false,
};

pub const SocketTable = struct {
    // Per-PID socket arrays; bounded by MAX_SOCKETS_PER_PID
    entries: std.AutoHashMap(u32, [MAX_SOCKETS_PER_PID]SocketEntry),
    counts: std.AutoHashMap(u32, u8),
    total_open: u64 = 0,
    total_close: u64 = 0,
    total_overflow: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) SocketTable {
        return .{
            .entries = std.AutoHashMap(u32, [MAX_SOCKETS_PER_PID]SocketEntry).init(allocator),
            .counts = std.AutoHashMap(u32, u8).init(allocator),
        };
    }

    pub fn deinit(self: *SocketTable) void {
        self.entries.deinit();
        self.counts.deinit();
    }

    pub fn open(self: *SocketTable, ev: HostEvent) bool {
        const pid = ev.pid;
        var arr = self.entries.get(pid) orelse [_]SocketEntry{.{}} ** MAX_SOCKETS_PER_PID;
        const cnt = self.counts.get(pid) orelse 0;
        if (cnt >= MAX_SOCKETS_PER_PID) {
            self.total_overflow += 1;
            return false;
        }
        arr[cnt] = .{
            .pid = pid,
            .proto = ev.proto,
            .local_ip = ev.local_ip,
            .local_port = ev.local_port,
            .remote_ip = ev.remote_ip,
            .remote_port = ev.remote_port,
            .opened_ns = ev.timestamp_ns,
        };
        self.entries.put(pid, arr) catch {};
        self.counts.put(pid, cnt + 1) catch {};
        self.total_open += 1;
        return true;
    }

    pub fn close(self: *SocketTable, ev: HostEvent) bool {
        const pid = ev.pid;
        const arr = self.entries.get(pid) orelse return false;
        const cnt = self.counts.get(pid) orelse return false;
        var i: u8 = 0;
        while (i < cnt) : (i += 1) {
            const e = arr[i];
            if (e.proto == ev.proto and
                std.mem.eql(u8, &e.local_ip, &ev.local_ip) and
                e.local_port == ev.local_port and
                std.mem.eql(u8, &e.remote_ip, &ev.remote_ip) and
                e.remote_port == ev.remote_port)
            {
                // Mark closed (compact by swapping with last)
                var mutable = arr;
                mutable[i] = mutable[cnt - 1];
                mutable[cnt - 1] = .{};
                self.entries.put(pid, mutable) catch {};
                self.counts.put(pid, cnt - 1) catch {};
                self.total_close += 1;
                return true;
            }
        }
        return false;
    }

    /// Find the PID owning a 4-tuple (proto, local, remote). Returns null
    /// if no live socket matches - this is the correlation key.
    pub fn findOwner(self: *const SocketTable, proto: SocketProto, local_ip: [4]u8, local_port: u16, remote_ip: [4]u8, remote_port: u16) ?u32 {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            const cnt = self.counts.get(entry.key_ptr.*) orelse 0;
            const arr = entry.value_ptr.*;
            var i: u8 = 0;
            while (i < cnt) : (i += 1) {
                const e = arr[i];
                if (e.closed) continue;
                if (e.proto != proto) continue;
                if (e.local_port != local_port or e.remote_port != remote_port) continue;
                if (!std.mem.eql(u8, &e.local_ip, &local_ip)) continue;
                if (!std.mem.eql(u8, &e.remote_ip, &remote_ip)) continue;
                return e.pid;
            }
        }
        return null;
    }

    pub fn socketsForPid(self: *const SocketTable, pid: u32) []const SocketEntry {
        const arr = self.entries.get(pid) orelse return &[_]SocketEntry{};
        const cnt = self.counts.get(pid) orelse 0;
        return arr[0..cnt];
    }

    pub fn pidCount(self: *const SocketTable) usize {
        return self.entries.count();
    }

    pub fn resetStats(self: *SocketTable) void {
        self.total_open = 0;
        self.total_close = 0;
        self.total_overflow = 0;
    }
};

// ============================================================
// CorrelatedIncident (network flow + host attribution)
// ============================================================

pub const CorrelatedIncident = struct {
    timestamp_ns: i64 = 0,
    severity: IncidentSeverity = .info,
    // Network side
    flow_local_ip: [4]u8 = .{ 0, 0, 0, 0 },
    flow_local_port: u16 = 0,
    flow_remote_ip: [4]u8 = .{ 0, 0, 0, 0 },
    flow_remote_port: u16 = 0,
    flow_proto: SocketProto = .tcp,
    flow_score: f32 = 0.0,
    flow_label: [16]u8 = [_]u8{0} ** 16,
    flow_label_len: u8 = 0,
    // Host side (PID responsible)
    attributed_pid: u32 = 0,
    attributed_image: [MAX_IMAGE_PATH]u8 = [_]u8{0} ** MAX_IMAGE_PATH,
    attributed_image_len: u16 = 0,
    attributed_cmdline: [MAX_CMDLINE]u8 = [_]u8{0} ** MAX_CMDLINE,
    attributed_cmdline_len: u16 = 0,
    attributed_signed: bool = false,
    attributed_integrity: ProcessIntegrity = .medium,
    parent_chain_len: u8 = 0,
    reasons: [MAX_REASONS]SuspicionReason = [_]SuspicionReason{.none} ** MAX_REASONS,
    reason_count: u8 = 0,

    pub fn attributedImage(self: *const CorrelatedIncident) []const u8 {
        return self.attributed_image[0..self.attributed_image_len];
    }
    pub fn attributedCmdline(self: *const CorrelatedIncident) []const u8 {
        return self.attributed_cmdline[0..self.attributed_cmdline_len];
    }
    pub fn flowLabel(self: *const CorrelatedIncident) []const u8 {
        return self.flow_label[0..self.flow_label_len];
    }
    pub fn addReason(self: *CorrelatedIncident, r: SuspicionReason) void {
        if (self.reason_count >= MAX_REASONS) return;
        // Dedup
        var i: u8 = 0;
        while (i < self.reason_count) : (i += 1) {
            if (self.reasons[i] == r) return;
        }
        self.reasons[self.reason_count] = r;
        self.reason_count += 1;
        // Bump severity
        if (r.isCritical() and @intFromEnum(self.severity) < @intFromEnum(IncidentSeverity.critical)) {
            self.severity = .critical;
        } else if (@intFromEnum(self.severity) < @intFromEnum(IncidentSeverity.high)) {
            self.severity = .high;
        }
    }
};

// ============================================================
// NetworkFlowVerdict (mirror of Phase 36 ML detector output - no import)
// ============================================================

pub const NetworkFlowVerdict = struct {
    timestamp_ns: i64 = 0,
    proto: SocketProto = .tcp,
    local_ip: [4]u8 = .{ 0, 0, 0, 0 },
    local_port: u16 = 0,
    remote_ip: [4]u8 = .{ 0, 0, 0, 0 },
    remote_port: u16 = 0,
    score: f32 = 0.0,
    label: [16]u8 = [_]u8{0} ** 16,
    label_len: u8 = 0,
    z_score: f32 = 0.0,

    pub fn labelStr(self: *const NetworkFlowVerdict) []const u8 {
        return self.label[0..self.label_len];
    }
};

// ============================================================
// CorrelationEngine (joins network verdicts with host telemetry)
// ============================================================

pub const CorrelationEngine = struct {
    allocator: std.mem.Allocator,
    tracker: *ProcessTracker,
    sockets: *SocketTable,
    incidents: [MAX_INCIDENTS]CorrelatedIncident = undefined,
    incident_count: usize = 0,
    config: HostConfig,
    total_correlated: u64 = 0,
    total_attributed: u64 = 0,
    total_unattributed: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, tracker: *ProcessTracker, sockets: *SocketTable, config: HostConfig) CorrelationEngine {
        return .{
            .allocator = allocator,
            .tracker = tracker,
            .sockets = sockets,
            .config = config,
        };
    }

    /// Process a network flow verdict from the ML detector. Returns the
    /// incident index (0..incident_count-1) if an incident was emitted,
    /// null otherwise (score below threshold, kill switch off, no owner).
    pub fn processFlowVerdict(self: *CorrelationEngine, v: NetworkFlowVerdict) ?usize {
        if (!self.config.enabled) return null;
        if (!self.config.enable_socket_correlation) return null;
        if (v.score < self.config.incident_score_threshold) return null;
        if (self.incident_count >= self.config.max_incidents) {
            // Ring buffer: drop oldest
            self.incident_count = self.config.max_incidents - 1;
            var i: usize = 0;
            while (i < self.incident_count) : (i += 1) {
                self.incidents[i] = self.incidents[i + 1];
            }
        }

        var inc = CorrelatedIncident{
            .timestamp_ns = v.timestamp_ns,
            .severity = if (v.score >= 0.9) .critical else .high,
            .flow_local_ip = v.local_ip,
            .flow_local_port = v.local_port,
            .flow_remote_ip = v.remote_ip,
            .flow_remote_port = v.remote_port,
            .flow_proto = v.proto,
            .flow_score = v.score,
            .flow_label_len = @intCast(@min(v.label_len, 16)),
        };
        @memcpy(inc.flow_label[0..inc.flow_label_len], v.label[0..inc.flow_label_len]);
        inc.addReason(.network_host_correlation);

        // Attribute to PID via socket table
        if (self.sockets.findOwner(v.proto, v.local_ip, v.local_port, v.remote_ip, v.remote_port)) |pid| {
            inc.attributed_pid = pid;
            self.total_attributed += 1;
            if (self.tracker.getProcess(pid)) |pi| {
                const img = pi.imagePath();
                @memcpy(inc.attributed_image[0..img.len], img);
                inc.attributed_image_len = @intCast(img.len);
                const cl = pi.commandLine();
                @memcpy(inc.attributed_cmdline[0..cl.len], cl);
                inc.attributed_cmdline_len = @intCast(cl.len);
                inc.attributed_signed = pi.is_signed;
                inc.attributed_integrity = pi.integrity;
                if (pi.isSuspicious()) {
                    inc.addReason(.parent_child_anomaly);
                }
                if (!pi.is_signed and pi.integrity.isElevated()) {
                    inc.addReason(.unsigned_elevated);
                }
                // Walk parent chain
                var chain: [PARENT_CHAIN_DEPTH]ProcessInfo = undefined;
                inc.parent_chain_len = @intCast(@min(
                    self.tracker.parentChain(pid, self.config.parent_chain_depth, &chain),
                    255,
                ));
            }
        } else {
            self.total_unattributed += 1;
        }

        self.total_correlated += 1;
        self.incidents[self.incident_count] = inc;
        const idx = self.incident_count;
        self.incident_count += 1;
        return idx;
    }

    pub fn getIncident(self: *const CorrelationEngine, idx: usize) ?*const CorrelatedIncident {
        if (idx >= self.incident_count) return null;
        return &self.incidents[idx];
    }

    pub fn incidentCount(self: *const CorrelationEngine) usize {
        return self.incident_count;
    }

    pub fn resetStats(self: *CorrelationEngine) void {
        self.total_correlated = 0;
        self.total_attributed = 0;
        self.total_unattributed = 0;
        self.incident_count = 0;
    }
};

// ============================================================
// HostTelemetry facade (singleton, project style)
// ============================================================

pub const HostTelemetry = struct {
    allocator: std.mem.Allocator,
    config: HostConfig,
    tracker: ProcessTracker,
    fim: FileIntegrityStore,
    reg: RegistryWatchQueue,
    sockets: SocketTable,
    correlator: CorrelationEngine,
    initialized: bool = false,

    var _instance: ?HostTelemetry = null;

    pub fn instance() ?*HostTelemetry {
        if (_instance) |*i| return i;
        return null;
    }

    pub fn init(allocator: std.mem.Allocator, config: HostConfig) !*HostTelemetry {
        if (_instance != null) return &_instance.?;
        _instance = HostTelemetry{
            .allocator = allocator,
            .config = config,
            .tracker = ProcessTracker.init(allocator, config.max_processes),
            .fim = FileIntegrityStore.init(allocator),
            .reg = RegistryWatchQueue.init(),
            .sockets = SocketTable.init(allocator),
            .correlator = undefined, // set below
        };
        var self = &_instance.?;
        self.correlator = CorrelationEngine.init(allocator, &self.tracker, &self.sockets, config);
        self.initialized = true;
        return self;
    }

    pub fn shutdown(self: *HostTelemetry) void {
        if (!self.initialized) return;
        self.tracker.deinit();
        self.fim.deinit();
        self.sockets.deinit();
        self.initialized = false;
        _instance = null;
    }

    pub fn isAvailable(self: *const HostTelemetry) bool {
        return self.initialized and self.config.enabled;
    }

    /// Ingest a host event from any source (ETW / FIM / RegistryNotify /
    /// Socket hook). Returns suspicion reason (none if clean / disabled).
    pub fn ingestEvent(self: *HostTelemetry, ev: HostEvent) SuspicionReason {
        if (!self.config.enabled) return .none;

        var reason: SuspicionReason = .none;
        switch (ev.event_type) {
            .process_create => {
                if (self.config.enable_process_tracking) {
                    reason = self.tracker.trackCreate(ev);
                }
            },
            .process_exit => {
                if (self.config.enable_process_tracking) {
                    self.tracker.trackExit(ev.pid, ev.timestamp_ns);
                }
            },
            .image_load => {
                // Future: signature validation, image load from suspicious path
            },
            .file_create, .file_modify, .file_delete => {
                if (self.config.enable_file_integrity) {
                    const path = ev.filePath();
                    const kind = self.fim.observe(path, ev.file_hash, ev.file_size, ev.timestamp_ns, ev.file_attrs, ev.event_type, ev.timestamp_ns);
                    switch (kind) {
                        .modified => reason = .file_integrity_mismatch,
                        .deleted => reason = .file_integrity_deleted,
                        else => {},
                    }
                }
            },
            .registry_set_value, .registry_create_key, .registry_delete_key => {
                if (self.config.enable_registry_watch) {
                    if (self.reg.enqueue(ev)) |r| reason = r;
                }
            },
            .socket_open => {
                if (self.config.enable_socket_correlation) {
                    _ = self.sockets.open(ev);
                }
            },
            .socket_close => {
                if (self.config.enable_socket_correlation) {
                    _ = self.sockets.close(ev);
                }
            },
        }
        return reason;
    }

    /// Push a network flow verdict (from Phase 36 ML detector) for host
    /// attribution. Returns incident index if one was emitted, else null.
    pub fn pushFlowVerdict(self: *HostTelemetry, v: NetworkFlowVerdict) ?usize {
        if (!self.config.enabled) return null;
        return self.correlator.processFlowVerdict(v);
    }
};

// ============================================================
// Tests
// ============================================================

test "HostConfig defaults - kill switch OFF" {
    const c = HostConfig{};
    try std.testing.expect(!c.enabled);
    try std.testing.expect(c.enable_process_tracking);
    try std.testing.expect(c.incident_score_threshold == 0.70);
}

test "ProcessIntegrity toString / isElevated" {
    try std.testing.expectEqualStrings("LOW", ProcessIntegrity.low.toString());
    try std.testing.expectEqualStrings("SYSTEM", ProcessIntegrity.system.toString());
    try std.testing.expect(!ProcessIntegrity.low.isElevated());
    try std.testing.expect(ProcessIntegrity.high.isElevated());
    try std.testing.expect(ProcessIntegrity.system.isElevated());
}

test "HostEventType isCritical" {
    try std.testing.expect(HostEventType.file_modify.isCritical());
    try std.testing.expect(HostEventType.registry_set_value.isCritical());
    try std.testing.expect(!HostEventType.process_create.isCritical());
    try std.testing.expect(!HostEventType.socket_open.isCritical());
}

test "SuspicionReason isCritical" {
    try std.testing.expect(SuspicionReason.file_integrity_mismatch.isCritical());
    try std.testing.expect(SuspicionReason.network_host_correlation.isCritical());
    try std.testing.expect(!SuspicionReason.parent_child_anomaly.isCritical());
    try std.testing.expect(!SuspicionReason.none.isCritical());
}

test "sha256 deterministic" {
    const h1 = sha256("hello");
    const h2 = sha256("hello");
    const h3 = sha256("world");
    try std.testing.expectEqualSlices(u8, &h1, &h2);
    try std.testing.expect(!std.mem.eql(u8, &h1, &h3));
    try std.testing.expect(h1[0] != h3[0] or h1[1] != h3[1]);
}

test "isSuspiciousParentChild detects office-spawning-shell" {
    try std.testing.expect(isSuspiciousParentChild(
        "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
        "C:\\Windows\\System32\\cmd.exe",
    ));
    try std.testing.expect(isSuspiciousParentChild(
        "EXCEL.EXE",
        "powershell.exe",
    ));
    try std.testing.expect(!isSuspiciousParentChild(
        "explorer.exe",
        "cmd.exe",
    ));
    try std.testing.expect(!isSuspiciousParentChild(
        "winword.exe",
        "iexplore.exe",
    ));
}

test "isInSystemPath" {
    try std.testing.expect(isInSystemPath("C:\\Windows\\System32\\svchost.exe"));
    try std.testing.expect(isInSystemPath("C:\\Windows\\SysWOW64\\dllhost.exe"));
    try std.testing.expect(!isInSystemPath("C:\\Users\\Public\\drop.exe"));
}

test "ProcessTracker tracks create and exit" {
    var t = ProcessTracker.init(std.testing.allocator, 64);
    defer t.deinit();

    var ev = HostEvent{
        .event_type = .process_create,
        .pid = 1234,
        .ppid = 100,
        .integrity = .medium,
        .is_signed = true,
        .timestamp_ns = 1000,
    };
    const img = "C:\\Windows\\System32\\notepad.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);

    const r = t.trackCreate(ev);
    try std.testing.expectEqual(SuspicionReason.none, r);
    try std.testing.expectEqual(@as(usize, 1), t.count());
    try std.testing.expectEqual(@as(usize, 1), t.aliveCount());

    t.trackExit(1234, 2000);
    try std.testing.expectEqual(@as(usize, 0), t.aliveCount());
    try std.testing.expectEqual(@as(u64, 1), t.total_create);
    try std.testing.expectEqual(@as(u64, 1), t.total_exit);
}

test "ProcessTracker detects office-spawning-shell anomaly" {
    var t = ProcessTracker.init(std.testing.allocator, 64);
    defer t.deinit();

    var parent = HostEvent{
        .event_type = .process_create,
        .pid = 100,
        .ppid = 4,
        .integrity = .medium,
        .is_signed = true,
        .timestamp_ns = 1000,
    };
    const pimg = "C:\\Program Files\\Office\\WINWORD.EXE";
    @memcpy(parent.image_path[0..pimg.len], pimg);
    parent.image_path_len = @intCast(pimg.len);
    _ = t.trackCreate(parent);

    var child = HostEvent{
        .event_type = .process_create,
        .pid = 200,
        .ppid = 100,
        .integrity = .medium,
        .is_signed = true,
        .timestamp_ns = 2000,
    };
    const cimg = "C:\\Windows\\System32\\cmd.exe";
    @memcpy(child.image_path[0..cimg.len], cimg);
    child.image_path_len = @intCast(cimg.len);
    const r = t.trackCreate(child);

    try std.testing.expectEqual(SuspicionReason.parent_child_anomaly, r);
    try std.testing.expectEqual(@as(u64, 1), t.suspicious_parent_pairs);
}

test "ProcessTracker detects unsigned elevated" {
    var t = ProcessTracker.init(std.testing.allocator, 64);
    defer t.deinit();
    var ev = HostEvent{
        .event_type = .process_create,
        .pid = 1234,
        .ppid = 0,
        .integrity = .high,
        .is_signed = false,
    };
    const img = "C:\\Users\\Public\\dropper.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);
    const r = t.trackCreate(ev);
    try std.testing.expectEqual(SuspicionReason.unsigned_elevated, r);
}

test "ProcessTracker detects unsigned system path" {
    var t = ProcessTracker.init(std.testing.allocator, 64);
    defer t.deinit();
    var ev = HostEvent{
        .event_type = .process_create,
        .pid = 1234,
        .ppid = 0,
        .integrity = .system,
        .is_signed = false,
    };
    const img = "C:\\Windows\\System32\\evil.dll";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);
    const r = t.trackCreate(ev);
    try std.testing.expectEqual(SuspicionReason.unsigned_system_path, r);
}

test "ProcessTracker parentChain walks ancestors" {
    var t = ProcessTracker.init(std.testing.allocator, 64);
    defer t.deinit();

    var ev = HostEvent{ .event_type = .process_create, .pid = 100, .ppid = 50, .timestamp_ns = 1000 };
    const img1 = "a.exe";
    @memcpy(ev.image_path[0..img1.len], img1);
    ev.image_path_len = img1.len;
    _ = t.trackCreate(ev);

    ev.pid = 200;
    ev.ppid = 100;
    ev.timestamp_ns = 2000;
    const img2 = "b.exe";
    @memcpy(ev.image_path[0..img2.len], img2);
    ev.image_path_len = img2.len;
    _ = t.trackCreate(ev);

    ev.pid = 300;
    ev.ppid = 200;
    ev.timestamp_ns = 3000;
    const img3 = "c.exe";
    @memcpy(ev.image_path[0..img3.len], img3);
    ev.image_path_len = img3.len;
    _ = t.trackCreate(ev);

    var chain: [4]ProcessInfo = undefined;
    const n = t.parentChain(300, 4, &chain);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(u32, 300), chain[0].pid);
    try std.testing.expectEqual(@as(u32, 200), chain[1].pid);
    try std.testing.expectEqual(@as(u32, 100), chain[2].pid);
}

test "FileIntegrityStore detects modification (hash mismatch)" {
    var fim = FileIntegrityStore.init(std.testing.allocator);
    defer fim.deinit();

    const path = "C:\\Windows\\System32\\svchost.exe";
    const h1 = sha256("clean-content");
    try fim.setBaseline(path, h1, 1024, 1000, 0x20, 2000);

    const h2 = sha256("tampered-content");
    const k = fim.observe(path, h2, 2048, 3000, 0x20, .file_modify, 4000);
    try std.testing.expectEqual(FileChangeKind.modified, k);
    try std.testing.expectEqual(@as(u64, 1), fim.total_mismatch);
}

test "FileIntegrityStore detects deletion" {
    var fim = FileIntegrityStore.init(std.testing.allocator);
    defer fim.deinit();

    const path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    const h = sha256("baseline");
    try fim.setBaseline(path, h, 100, 1000, 0x20, 2000);

    const k = fim.observe(path, [_]u8{0} ** SHA256_LEN, 0, 0, 0, .file_delete, 3000);
    try std.testing.expectEqual(FileChangeKind.deleted, k);
    try std.testing.expectEqual(@as(u64, 1), fim.total_deleted);
}

test "FileIntegrityStore detects new file (no baseline)" {
    var fim = FileIntegrityStore.init(std.testing.allocator);
    defer fim.deinit();

    const path = "C:\\Users\\Public\\newly_dropped.exe";
    const h = sha256("payload");
    const k = fim.observe(path, h, 4096, 1000, 0x20, .file_create, 2000);
    try std.testing.expectEqual(FileChangeKind.created, k);
    try std.testing.expectEqual(@as(u64, 1), fim.total_created);
}

test "FileIntegrityStore returns none for matching baseline" {
    var fim = FileIntegrityStore.init(std.testing.allocator);
    defer fim.deinit();

    const path = "C:\\Windows\\System32\\kernel32.dll";
    const h = sha256("content");
    try fim.setBaseline(path, h, 1024, 1000, 0x20, 2000);

    const k = fim.observe(path, h, 1024, 3000, 0x20, .file_modify, 4000);
    try std.testing.expectEqual(FileChangeKind.none, k);
}

test "RegistryWatchQueue default persistence keys installed" {
    const q = RegistryWatchQueue.init();
    try std.testing.expect(q.persistence_keys_count >= 5);
    try std.testing.expect(q.critical_keys_count >= 4);
}

test "RegistryWatchQueue classifies persistence Run key" {
    var q = RegistryWatchQueue.init();

    var ev = HostEvent{
        .event_type = .registry_set_value,
        .pid = 1234,
        .timestamp_ns = 1000,
    };
    const k = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor";
    @memcpy(ev.reg_key[0..k.len], k);
    ev.reg_key_len = @intCast(k.len);
    const vn = "Updater";
    @memcpy(ev.reg_value_name[0..vn.len], vn);
    ev.reg_value_name_len = vn.len;

    const r = q.enqueue(ev) orelse return error.TestExpectedReason;
    try std.testing.expectEqual(SuspicionReason.registry_persistence_key, r);
    try std.testing.expectEqual(@as(u64, 1), q.total_persistence_hits);
}

test "RegistryWatchQueue classifies SAM critical key" {
    var q = RegistryWatchQueue.init();

    var ev = HostEvent{
        .event_type = .registry_set_value,
        .pid = 1234,
        .timestamp_ns = 1000,
    };
    const k = "\\REGISTRY\\MACHINE\\SAM\\SAM\\Domains\\Account";
    @memcpy(ev.reg_key[0..k.len], k);
    ev.reg_key_len = @intCast(k.len);

    const r = q.enqueue(ev) orelse return error.TestExpectedReason;
    try std.testing.expectEqual(SuspicionReason.registry_critical_key, r);
    try std.testing.expectEqual(@as(u64, 1), q.total_critical_hits);
}

test "RegistryWatchQueue drains pending changes" {
    var q = RegistryWatchQueue.init();
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        var ev = HostEvent{
            .event_type = .registry_set_value,
            .pid = i,
            .timestamp_ns = @intCast(i),
        };
        const k = "\\REGISTRY\\USER\\SOFTWARE\\Foo";
        @memcpy(ev.reg_key[0..k.len], k);
        ev.reg_key_len = k.len;
        _ = q.enqueue(ev);
    }
    try std.testing.expectEqual(@as(usize, 3), q.count);

    var out: [8]RegistryChange = undefined;
    const n = q.drain(&out);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(usize, 0), q.count);
}

test "SocketTable opens and finds owner" {
    var st = SocketTable.init(std.testing.allocator);
    defer st.deinit();

    const ev = HostEvent{
        .event_type = .socket_open,
        .pid = 1234,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 51000,
        .remote_ip = .{ 47, 239, 134, 228 },
        .remote_port = 443,
        .timestamp_ns = 1000,
    };
    try std.testing.expect(st.open(ev));

    const owner = st.findOwner(.tcp, .{ 192, 168, 1, 41 }, 51000, .{ 47, 239, 134, 228 }, 443);
    try std.testing.expectEqual(@as(u32, 1234), owner.?);
}

test "SocketTable close removes the entry" {
    var st = SocketTable.init(std.testing.allocator);
    defer st.deinit();

    var ev = HostEvent{
        .event_type = .socket_open,
        .pid = 1234,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 51000,
        .remote_ip = .{ 47, 239, 134, 228 },
        .remote_port = 443,
        .timestamp_ns = 1000,
    };
    _ = st.open(ev);

    ev.event_type = .socket_close;
    try std.testing.expect(st.close(ev));

    const owner = st.findOwner(.tcp, .{ 192, 168, 1, 41 }, 51000, .{ 47, 239, 134, 228 }, 443);
    try std.testing.expect(owner == null);
}

test "SocketTable bounds per-PID sockets" {
    var st = SocketTable.init(std.testing.allocator);
    defer st.deinit();

    var i: u16 = 0;
    while (i < MAX_SOCKETS_PER_PID + 5) : (i += 1) {
        const ev = HostEvent{
            .event_type = .socket_open,
            .pid = 1,
            .proto = .tcp,
            .local_ip = .{ 192, 168, 1, 41 },
            .local_port = 40000 + i,
            .remote_ip = .{ 1, 2, 3, 4 },
            .remote_port = 80,
            .timestamp_ns = 1000,
        };
        _ = st.open(ev);
    }
    try std.testing.expectEqual(@as(u64, 5), st.total_overflow);
}

test "CorrelatedIncident addReason bumps severity and dedups" {
    var inc = CorrelatedIncident{};
    try std.testing.expectEqual(IncidentSeverity.info, inc.severity);
    try std.testing.expectEqual(@as(u8, 0), inc.reason_count);

    inc.addReason(.parent_child_anomaly);
    try std.testing.expectEqual(IncidentSeverity.high, inc.severity);
    try std.testing.expectEqual(@as(u8, 1), inc.reason_count);

    inc.addReason(.network_host_correlation);
    try std.testing.expectEqual(IncidentSeverity.critical, inc.severity);
    try std.testing.expectEqual(@as(u8, 2), inc.reason_count);

    inc.addReason(.network_host_correlation); // dup, ignored
    try std.testing.expectEqual(@as(u8, 2), inc.reason_count);
}

test "CorrelationEngine attributes malicious flow to PID" {
    const alloc = std.testing.allocator;
    var tracker = ProcessTracker.init(alloc, 64);
    defer tracker.deinit();
    var st = SocketTable.init(alloc);
    defer st.deinit();

    var proc_ev = HostEvent{
        .event_type = .process_create,
        .pid = 4321,
        .ppid = 100,
        .integrity = .high,
        .is_signed = false,
        .timestamp_ns = 1000,
    };
    const img = "C:\\Users\\Public\\malware.exe";
    @memcpy(proc_ev.image_path[0..img.len], img);
    proc_ev.image_path_len = @intCast(img.len);
    _ = tracker.trackCreate(proc_ev);

    const sock_ev = HostEvent{
        .event_type = .socket_open,
        .pid = 4321,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 51000,
        .remote_ip = .{ 203, 0, 113, 5 },
        .remote_port = 4444,
        .timestamp_ns = 2000,
    };
    _ = st.open(sock_ev);

    var eng = CorrelationEngine.init(alloc, &tracker, &st, .{ .enabled = true });
    var v = NetworkFlowVerdict{
        .timestamp_ns = 3000,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 51000,
        .remote_ip = .{ 203, 0, 113, 5 },
        .remote_port = 4444,
        .score = 0.95,
    };
    const lbl = "malicious";
    @memcpy(v.label[0..lbl.len], lbl);
    v.label_len = lbl.len;

    const idx = eng.processFlowVerdict(v) orelse return error.TestExpectedIncident;
    const inc = eng.getIncident(idx).?;
    try std.testing.expectEqual(@as(u32, 4321), inc.attributed_pid);
    try std.testing.expectEqualStrings("C:\\Users\\Public\\malware.exe", inc.attributedImage());
    try std.testing.expectEqual(IncidentSeverity.critical, inc.severity);
    try std.testing.expect(inc.reason_count >= 2); // network_host_correlation + unsigned_elevated
    try std.testing.expectEqual(@as(u64, 1), eng.total_attributed);
}

test "CorrelationEngine skips low-score flows" {
    const alloc = std.testing.allocator;
    var tracker = ProcessTracker.init(alloc, 64);
    defer tracker.deinit();
    var st = SocketTable.init(alloc);
    defer st.deinit();

    var eng = CorrelationEngine.init(alloc, &tracker, &st, .{ .enabled = true });
    const v = NetworkFlowVerdict{
        .timestamp_ns = 1000,
        .score = 0.40, // below 0.70 threshold
    };
    const r = eng.processFlowVerdict(v);
    try std.testing.expect(r == null);
    try std.testing.expectEqual(@as(usize, 0), eng.incidentCount());
}

test "CorrelationEngine respects kill switch" {
    const alloc = std.testing.allocator;
    var tracker = ProcessTracker.init(alloc, 64);
    defer tracker.deinit();
    var st = SocketTable.init(alloc);
    defer st.deinit();

    var eng = CorrelationEngine.init(alloc, &tracker, &st, .{ .enabled = false });
    const v = NetworkFlowVerdict{ .timestamp_ns = 1000, .score = 0.99 };
    try std.testing.expect(eng.processFlowVerdict(v) == null);
}

test "HostTelemetry singleton init/shutdown" {
    const alloc = std.testing.allocator;
    {
        var ht = try HostTelemetry.init(alloc, .{});
        defer ht.shutdown();
        try std.testing.expect(ht.isAvailable() == false); // enabled=false

        const ht2 = HostTelemetry.instance();
        try std.testing.expect(ht2 != null);
    }
    try std.testing.expect(HostTelemetry.instance() == null);
}

test "HostTelemetry ingestEvent respects kill switch" {
    const alloc = std.testing.allocator;
    var ht = try HostTelemetry.init(alloc, .{ .enabled = false });
    defer ht.shutdown();

    var ev = HostEvent{
        .event_type = .process_create,
        .pid = 1234,
        .ppid = 100,
        .integrity = .high,
        .is_signed = false,
    };
    const img = "C:\\Windows\\System32\\evil.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);

    const r = ht.ingestEvent(ev);
    try std.testing.expectEqual(SuspicionReason.none, r);
    try std.testing.expectEqual(@as(usize, 0), ht.tracker.count());
}

test "HostTelemetry ingestEvent routes process_create" {
    const alloc = std.testing.allocator;
    var ht = try HostTelemetry.init(alloc, .{ .enabled = true });
    defer ht.shutdown();

    var ev = HostEvent{
        .event_type = .process_create,
        .pid = 1234,
        .ppid = 100,
        .integrity = .high,
        .is_signed = false,
        .timestamp_ns = 1000,
    };
    const img = "C:\\Windows\\System32\\evil.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);

    const r = ht.ingestEvent(ev);
    try std.testing.expectEqual(SuspicionReason.unsigned_system_path, r);
    try std.testing.expectEqual(@as(usize, 1), ht.tracker.count());
}

test "HostTelemetry ingestEvent routes file_modify" {
    const alloc = std.testing.allocator;
    var ht = try HostTelemetry.init(alloc, .{ .enabled = true });
    defer ht.shutdown();

    const path = "C:\\Windows\\System32\\svchost.exe";
    const h = sha256("clean");
    try ht.fim.setBaseline(path, h, 1024, 1000, 0x20, 2000);

    var ev = HostEvent{
        .event_type = .file_modify,
        .pid = 1234,
        .timestamp_ns = 3000,
        .file_size = 2048,
        .file_attrs = 0x20,
    };
    @memcpy(ev.file_path[0..path.len], path);
    ev.file_path_len = @intCast(path.len);
    const h2 = sha256("tampered");
    @memcpy(ev.file_hash[0..SHA256_LEN], &h2);

    const r = ht.ingestEvent(ev);
    try std.testing.expectEqual(SuspicionReason.file_integrity_mismatch, r);
}

test "HostTelemetry ingestEvent routes registry_set_value" {
    const alloc = std.testing.allocator;
    var ht = try HostTelemetry.init(alloc, .{ .enabled = true });
    defer ht.shutdown();

    var ev = HostEvent{
        .event_type = .registry_set_value,
        .pid = 1234,
        .timestamp_ns = 1000,
    };
    const k = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil";
    @memcpy(ev.reg_key[0..k.len], k);
    ev.reg_key_len = @intCast(k.len);

    const r = ht.ingestEvent(ev);
    try std.testing.expectEqual(SuspicionReason.registry_persistence_key, r);
}

test "HostTelemetry end-to-end: process -> socket -> malicious flow -> incident" {
    const alloc = std.testing.allocator;
    var ht = try HostTelemetry.init(alloc, .{ .enabled = true });
    defer ht.shutdown();

    // 1. Process launches (unsigned, suspicious)
    var pe = HostEvent{
        .event_type = .process_create,
        .pid = 999,
        .ppid = 4,
        .integrity = .high,
        .is_signed = false,
        .timestamp_ns = 1000,
    };
    const img = "C:\\Users\\Public\\dropper.exe";
    @memcpy(pe.image_path[0..img.len], img);
    pe.image_path_len = @intCast(img.len);
    _ = ht.ingestEvent(pe);

    // 2. Process opens a TCP socket to a C2 server
    const se = HostEvent{
        .event_type = .socket_open,
        .pid = 999,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 51000,
        .remote_ip = .{ 198, 51, 100, 7 },
        .remote_port = 4444,
        .timestamp_ns = 2000,
    };
    _ = ht.ingestEvent(se);

    // 3. ML detector emits a malicious verdict for that 4-tuple
    var v = NetworkFlowVerdict{
        .timestamp_ns = 3000,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 51000,
        .remote_ip = .{ 198, 51, 100, 7 },
        .remote_port = 4444,
        .score = 0.93,
    };
    const lbl = "malicious";
    @memcpy(v.label[0..lbl.len], lbl);
    v.label_len = lbl.len;

    const idx = ht.pushFlowVerdict(v) orelse return error.TestExpectedIncident;
    const inc = ht.correlator.getIncident(idx).?;
    try std.testing.expectEqual(@as(u32, 999), inc.attributed_pid);
    try std.testing.expectEqualStrings("C:\\Users\\Public\\dropper.exe", inc.attributedImage());
    try std.testing.expectEqual(IncidentSeverity.critical, inc.severity);
    try std.testing.expectEqual(@as(f32, 0.93), inc.flow_score);
}
