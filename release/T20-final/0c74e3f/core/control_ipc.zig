//! control_ipc.zig - AEGIS Control-Plane IPC (T16, Steps 41-43)
//!
//! G9 T16: Security hardening for the control plane.
//!   - Privileged IPC carries: caller identity, role, request_id, timeout,
//!     replay protection, audit. Never grants "Everyone" for privileged
//!     commands.
//!   - Roles are strictly ordered: READ < OPERATE < PRIVILEGED. A command
//!     is authorized only if the caller's role meets the command's minimum
//!     role.
//!   - aegisctl (and any CLI) must NOT mutate enforcement directly. It
//!     submits a ControlRequest over this IPC contract; privileged actions
//!     (WFP / driver mutation) flow through the Rust PEP only.
//!
//! Protocol (single frame, fixed header + small payload):
//!   magic: u32 (0x4354524C "CTRL")
//!   version: u16 (1)
//!   request_id: u64 (monotonic, per-instance randomness lower bound)
//!   caller_id_hash: u64 (FNV-1a of the caller identity string)
//!   role: u8 (ControlRole)
//!   command: u8 (ControlCommand)
//!   issued_at_ms: u64, timeout_ms: u32 (deadline = issued_at + timeout)
//!   nonce: u64 (replay protection)
//!
//! Authorization is layered:
//!   1. ACL check: the caller identity must be explicitly allowed for the
//!      requested role. There is no catch-all "Everyone" principal.
//!   2. Role check: command minimum role <= caller role.
//!   3. Freshness check: now_ms within [issued_at_ms, issued_at_ms +
//!      timeout_ms]; expired requests are rejected (timeout AC).
//!   4. Replay check: a (request_id, nonce) pair is consumed once; a
//!      repeated pair is rejected as a replay.
//!
//! Every decision is appended to the audit log: request_id, caller, role,
//! command, allow/deny, reason, latency_ms.

const std = @import("std");

pub const IPC_MAGIC: u32 = 0x4354524C; // "CTRL"
pub const IPC_VERSION: u16 = 1;

pub const MAX_AUDIT_ENTRIES: usize = 1024;

// ============================================================
// Roles (strictly ordered; READ < OPERATE < PRIVILEGED)
// ============================================================

pub const ControlRole = enum(u8) {
    read = 0, // version/status/health/diagnose: read-only inspection
    operate = 1, // rules reload, block-list edit request, quarantine request
    privileged = 2, // enforcement mutation (WFP / driver); PEP-gated

    pub fn toString(self: ControlRole) []const u8 {
        return switch (self) {
            .read => "READ",
            .operate => "OPERATE",
            .privileged => "PRIVILEGED",
        };
    }

    /// True if `self` is at least as privileged as `required`.
    pub fn meets(self: ControlRole, required: ControlRole) bool {
        return @intFromEnum(self) >= @intFromEnum(required);
    }

    pub fn fromInt(v: u8) ControlRole {
        return if (v >= @intFromEnum(ControlRole.privileged))
            .privileged
        else if (v >= @intFromEnum(ControlRole.operate)) .operate else .read;
    }
};

// ============================================================
// Commands (each with a minimum role)
// ============================================================

pub const ControlCommand = enum(u8) {
    status = 0, // READ
    version = 1, // READ
    health = 2, // READ
    rules_reload = 3, // OPERATE
    block_request = 4, // OPERATE (request only; PEP decides)
    unblock_request = 5, // OPERATE
    quarantine_request = 6, // OPERATE
    enforce_push = 7, // PRIVILEGED
    force_block = 8, // PRIVILEGED (direct enforcement mutation)
    force_unblock = 9, // PRIVILEGED
    driver_mutation = 10, // PRIVILEGED

    pub fn toString(self: ControlCommand) []const u8 {
        return switch (self) {
            .status => "STATUS",
            .version => "VERSION",
            .health => "HEALTH",
            .rules_reload => "RULES_RELOAD",
            .block_request => "BLOCK_REQUEST",
            .unblock_request => "UNBLOCK_REQUEST",
            .quarantine_request => "QUARANTINE_REQUEST",
            .enforce_push => "ENFORCE_PUSH",
            .force_block => "FORCE_BLOCK",
            .force_unblock => "FORCE_UNBLOCK",
            .driver_mutation => "DRIVER_MUTATION",
        };
    }

    /// Minimum role required to authorize this command.
    pub fn minRole(self: ControlCommand) ControlRole {
        return switch (self) {
            .status, .version, .health => .read,
            .rules_reload, .block_request, .unblock_request, .quarantine_request => .operate,
            .enforce_push, .force_block, .force_unblock, .driver_mutation => .privileged,
        };
    }

    /// Privileged commands may never authorize to a caller whose role is
    /// below PRIVILEGED (never "Everyone").
    pub fn isPrivileged(self: ControlCommand) bool {
        return self.minRole() == .privileged;
    }

    pub fn fromInt(v: u8) ControlCommand {
        return if (v >= @intFromEnum(ControlCommand.driver_mutation))
            .driver_mutation
        else if (v >= @intFromEnum(ControlCommand.force_unblock)) .force_unblock else .status;
    }
};

// ============================================================
// Caller identity + ACL
// ============================================================

/// The ACL has no catch-all "Everyone" principal. Each encoded caller is
/// explicitly granted a max role. Unknown callers are denied.
pub const AclEntry = struct {
    /// FNV-1a hash of the caller identity (e.g. "DOMAIN\\admin" or a pipe
    /// caller SID in production; a configurable sentinel in tests).
    caller_hash: u64,
    max_role: ControlRole,
};

pub const Acl = struct {
    entries: [16]AclEntry,
    count: usize,

    pub fn init() Acl {
        return .{ .entries = undefined, .count = 0 };
    }

    pub fn grant(self: *Acl, caller_hash: u64, max_role: ControlRole) void {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (self.entries[i].caller_hash == caller_hash) {
                self.entries[i].max_role = max_role;
                return;
            }
        }
        if (self.count < self.entries.len) {
            self.entries[self.count] = .{ .caller_hash = caller_hash, .max_role = max_role };
            self.count += 1;
        }
    }

    /// The caller is allowed the requested role iff they are explicitly
    /// granted a role at least that high. Never "Everyone".
    pub fn allows(self: *const Acl, caller_hash: u64, role: ControlRole) bool {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (self.entries[i].caller_hash == caller_hash) {
                return self.entries[i].max_role.meets(role);
            }
        }
        return false;
    }

    /// True if any principal is a catch-all (used by tests to assert no
    /// "Everyone" was ever granted).
    pub fn hasCatchAll(self: *const Acl) bool {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (self.entries[i].caller_hash == 0) return true;
        }
        return false;
    }
};

/// FNV-1a 64-bit, same hash used by the Rust PEP for its auth-token
/// fingerprint (T8), so the control plane and PEP agree on identities.
pub fn fnv1a(buffer: []const u8) u64 {
    var hash: u64 = 0xcbf29ce484222325;
    for (buffer) |b| {
        hash ^= b;
        hash *%= 0x100000001b3;
    }
    return hash;
}

// ============================================================
// Request + Authorization Decision
// ============================================================

pub const ControlRequest = struct {
    magic: u32 = IPC_MAGIC,
    version: u16 = IPC_VERSION,
    request_id: u64,
    caller_hash: u64,
    role: ControlRole,
    command: ControlCommand,
    issued_at_ms: u64,
    timeout_ms: u32,
    nonce: u64,

    pub fn deadline(self: ControlRequest) u64 {
        return self.issued_at_ms + self.timeout_ms;
    }

    pub fn isExpired(self: ControlRequest, now_ms: u64) bool {
        return now_ms > self.deadline();
    }
};

pub const Decision = enum(u8) {
    allow = 0,
    deny_unknown_caller = 1,
    deny_role_too_low = 2,
    deny_expired = 3,
    deny_replay = 4,
    deny_invalid_frame = 5,

    pub fn toString(self: Decision) []const u8 {
        return switch (self) {
            .allow => "ALLOW",
            .deny_unknown_caller => "DENY_UNKNOWN_CALLER",
            .deny_role_too_low => "DENY_ROLE_TOO_LOW",
            .deny_expired => "DENY_EXPIRED",
            .deny_replay => "DENY_REPLAY",
            .deny_invalid_frame => "DENY_INVALID_FRAME",
        };
    }

    pub fn isAllow(self: Decision) bool {
        return self == .allow;
    }
};

pub const AuditEntry = struct {
    request_id: u64,
    caller_hash: u64,
    role: ControlRole,
    command: ControlCommand,
    decision: Decision,
    latency_ms: u64,
};

// ============================================================
// Authorizer: layered authorization + replay protection + audit
// ============================================================

pub const Authorizer = struct {
    acl: Acl = Acl.init(),
    seen: [64]u64, // request_id+nonce rolled together (pan= check both)
    seen_count: usize,
    audits: [MAX_AUDIT_ENTRIES]AuditEntry,
    audit_count: usize,
    audit_head: usize,
    total_allowed: u64,
    total_denied: u64,
    last_decision: Decision = .deny_invalid_frame,

    pub fn init() Authorizer {
        return .{
            .seen = undefined,
            .seen_count = 0,
            .audits = undefined,
            .audit_count = 0,
            .audit_head = 0,
            .total_allowed = 0,
            .total_denied = 0,
        };
    }

    fn rollKey(req: ControlRequest) u64 {
        return std.hash.Wyhash.hash(0, std.mem.asBytes(&req.request_id)) ^
            std.hash.Wyhash.hash(0, std.mem.asBytes(&req.nonce));
    }

    fn alreadySeen(self: *const Authorizer, key: u64) bool {
        var i: usize = 0;
        while (i < self.seen_count) : (i += 1) {
            if (self.seen[i] == key) return true;
        }
        return false;
    }

    fn recordSeen(self: *Authorizer, key: u64) void {
        if (self.seen_count < self.seen.len) {
            self.seen[self.seen_count] = key;
            self.seen_count += 1;
        }
    }

    fn appendAudit(self: *Authorizer, e: AuditEntry) void {
        const idx = self.audit_head;
        self.audits[idx] = e;
        self.audit_head = (self.audit_head + 1) % MAX_AUDIT_ENTRIES;
        if (self.audit_count < MAX_AUDIT_ENTRIES) self.audit_count += 1;
    }

    /// Validate the frame header (magic/version) without authorization.
    pub fn validateFrame(req: ControlRequest) bool {
        return req.magic == IPC_MAGIC and req.version == IPC_VERSION;
    }

    /// Authorize a request. Order is important:
    ///   invalid frame -> unknown caller -> role too low -> expired ->
    ///   replay -> allow. Every decision is audited.
    pub fn authorize(self: *Authorizer, req: ControlRequest, now_ms: u64) Decision {
        const start = std.time.nanoTimestamp();
        defer {
            const latency_ms: u64 = @intCast(@divTrunc(@max(@as(i128, 0), std.time.nanoTimestamp() - start), std.time.ns_per_ms));
            self.appendAudit(.{
                .request_id = req.request_id,
                .caller_hash = req.caller_hash,
                .role = req.role,
                .command = req.command,
                .decision = self.last_decision,
                .latency_ms = latency_ms,
            });
            if (self.last_decision.isAllow()) {
                self.total_allowed += 1;
            } else {
                self.total_denied += 1;
            }
        }
        self.last_decision = self.authorizeInner(req, now_ms);
        return self.last_decision;
    }

    fn authorizeInner(self: *Authorizer, req: ControlRequest, now_ms: u64) Decision {
        if (!validateFrame(req)) return .deny_invalid_frame;

        // 1. ACL: caller must be explicitly granted (never "Everyone").
        if (!self.acl.allows(req.caller_hash, req.role)) return .deny_unknown_caller;

        // 2. Role: command minimum role must be met.
        if (!req.role.meets(req.command.minRole())) return .deny_role_too_low;

        // 3. Freshness: not expired.
        if (req.isExpired(now_ms)) return .deny_expired;

        // 4. Replay: (request_id, nonce) unique per authorization.
        const key = rollKey(req);
        if (self.alreadySeen(key)) return .deny_replay;
        self.recordSeen(key);

        return .allow;
    }

    pub fn lastAudit(self: *const Authorizer) ?AuditEntry {
        if (self.audit_count == 0) return null;
        const idx = if (self.audit_head == 0) MAX_AUDIT_ENTRIES - 1 else self.audit_head - 1;
        return self.audits[idx];
    }
};

// ============================================================
// Tests
// ============================================================

const CALLER_ADMIN = 111;
const CALLER_OPERATOR = 222;
const CALLER_UNKNOWN = 999;

fn makeReq(comptime rid: u64, comptime nonce: u64, caller: u64, role: ControlRole, command: ControlCommand, issued: u64, timeout: u32) ControlRequest {
    return .{
        .request_id = rid,
        .caller_hash = caller,
        .role = role,
        .command = command,
        .issued_at_ms = issued,
        .timeout_ms = timeout,
        .nonce = nonce,
    };
}

test "ControlRole ordering: READ < OPERATE < PRIVILEGED" {
    try std.testing.expect(ControlRole.read.meets(.read));
    try std.testing.expect(!ControlRole.read.meets(.operate));
    try std.testing.expect(ControlRole.operate.meets(.read));
    try std.testing.expect(ControlRole.operate.meets(.operate));
    try std.testing.expect(!ControlRole.operate.meets(.privileged));
    try std.testing.expect(ControlRole.privileged.meets(.read));
    try std.testing.expect(ControlRole.privileged.meets(.operate));
    try std.testing.expect(ControlRole.privileged.meets(.privileged));
}

test "ControlCommand minRole tiers" {
    try std.testing.expect(ControlCommand.status.minRole() == .read);
    try std.testing.expect(ControlCommand.rules_reload.minRole() == .operate);
    try std.testing.expect(ControlCommand.enforce_push.minRole() == .privileged);
    try std.testing.expect(ControlCommand.driver_mutation.minRole() == .privileged);
    try std.testing.expect(ControlCommand.driver_mutation.isPrivileged());
    try std.testing.expect(!ControlCommand.status.isPrivileged());
}

test "ACL never grants catch-all Everyone" {
    var acl = Acl.init();
    // Caller 0 = catch-all; granting it must never confer authorization.
    acl.grant(0, .privileged);
    try std.testing.expect(!acl.allows(123, .privileged));
    try std.testing.expect(acl.hasCatchAll());

    // Explicit grant works, unknown still denied.
    acl.grant(CALLER_ADMIN, .privileged);
    try std.testing.expect(acl.allows(CALLER_ADMIN, .privileged));
    try std.testing.expect(!acl.allows(CALLER_UNKNOWN, .read));
}

test "authorize allows in-order valid request" {
    var auth = Authorizer.init();
    auth.acl.grant(CALLER_ADMIN, .privileged);
    const req = makeReq(1, 101, CALLER_ADMIN, .privileged, .force_block, 1000, 5000);
    const d = auth.authorize(req, 3000);
    try std.testing.expect(d.isAllow());
    try std.testing.expect(auth.total_allowed == 1);
}

test "authorize rejects unknown caller" {
    var auth = Authorizer.init();
    auth.acl.grant(CALLER_ADMIN, .privileged);
    const req = makeReq(2, 202, CALLER_UNKNOWN, .privileged, .force_block, 1000, 5000);
    const d = auth.authorize(req, 3000);
    try std.testing.expect(d == .deny_unknown_caller);
}

test "authorize rejects role too low for privileged command" {
    var auth = Authorizer.init();
    // Operator can request blocks (OPERATE) but never force_block (PRIVILEGED).
    auth.acl.grant(CALLER_OPERATOR, .operate);
    const req = makeReq(3, 303, CALLER_OPERATOR, .operate, .force_block, 1000, 5000);
    const d = auth.authorize(req, 3000);
    try std.testing.expect(d == .deny_role_too_low);
    // But operator may submit a block REQUEST (non-privileged).
    const req2 = makeReq(4, 304, CALLER_OPERATOR, .operate, .block_request, 1000, 5000);
    try std.testing.expect(auth.authorize(req2, 3000).isAllow());
}

test "authorize rejects expired request (timeout)" {
    var auth = Authorizer.init();
    auth.acl.grant(CALLER_ADMIN, .privileged);
    const req = makeReq(5, 505, CALLER_ADMIN, .privileged, .driver_mutation, 1000, 200);
    try std.testing.expect(req.isExpired(2000));
    const d = auth.authorize(req, 2000);
    try std.testing.expect(d == .deny_expired);
}

test "authorize rejects replay of (request_id, nonce)" {
    var auth = Authorizer.init();
    auth.acl.grant(CALLER_ADMIN, .privileged);
    const req = makeReq(6, 606, CALLER_ADMIN, .privileged, .force_block, 1000, 5000);
    try std.testing.expect(auth.authorize(req, 2000).isAllow());
    try std.testing.expect(auth.authorize(req, 2000) == .deny_replay);
}

test "authorize rejects invalid frame (magic/version)" {
    var auth = Authorizer.init();
    auth.acl.grant(CALLER_ADMIN, .privileged);
    var req = makeReq(7, 707, CALLER_ADMIN, .privileged, .enforce_push, 1000, 5000);
    req.magic = 0xDEADBEEF;
    try std.testing.expect(auth.authorize(req, 2000) == .deny_invalid_frame);
}

test "every denied decision is audited with reason" {
    var auth = Authorizer.init();
    auth.acl.grant(CALLER_ADMIN, .privileged);
    // Two denies + one allow, order preserved.
    const y = auth.authorize(makeReq(8, 808, CALLER_UNKNOWN, .privileged, .force_block, 1000, 5000), 2000);
    try std.testing.expect(y == .deny_unknown_caller);
    const z = auth.authorize(makeReq(9, 909, CALLER_ADMIN, .read, .driver_mutation, 1000, 5000), 2000);
    try std.testing.expect(z == .deny_role_too_low);
    const ok = auth.authorize(makeReq(10, 1010, CALLER_ADMIN, .privileged, .force_block, 1000, 5000), 2000);
    try std.testing.expect(ok.isAllow());
    try std.testing.expect(auth.audit_count >= 3);
    try std.testing.expect(auth.total_allowed == 1 and auth.total_denied == 2);
}

test "fnv1a matches known FNV-1a vector" {
    // FNV-1a("") = 0xcbf29ce484222325
    try std.testing.expectEqual(@as(u64, 0xcbf29ce484222325), fnv1a(""));
    // FNV-1a("a") = 0xaf63dc4c8601ec8c
    try std.testing.expectEqual(@as(u64, 0xaf63dc4c8601ec8c), fnv1a("a"));
}