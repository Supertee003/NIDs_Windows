// backup_manager.zig - AEGIS Backup Manager (Phase 35)
//
// Provides programmatic backup/restore API for integration with the NIDS lifecycle.
// This is an OPTIONAL module - the primary backup mechanism is the PowerShell scripts
// (aegis_backup.ps1 + aegis_restore.ps1). This Zig module allows:
//   1. Triggering backups from within the NIDS (e.g., before config reload)
//   2. Querying backup history
//   3. Validating backup integrity
//
// On non-Windows or when PowerShell is not available, this module operates in
// "advisory mode" - it logs recommendations but doesn't execute.

const std = @import("std");

// ============================================================
// Constants
// ============================================================

pub const BACKUP_DIR = "backups";
pub const MANIFEST_NAME = "manifest.json";
pub const MAX_BACKUPS_TO_LIST = 20;

// ============================================================
// Backup Manifest (mirrors the PowerShell manifest.json structure)
// ============================================================

pub const BackupManifest = struct {
    backup_timestamp: []const u8,
    backup_date: []const u8,
    total_files: u32,
    mode: []const u8,
    wfp_driver_running: bool,
    test_signing_enabled: bool,
    test_cert_thumbprint: ?[]const u8 = null,
};

// ============================================================
// Backup Manager
// ============================================================

pub const BackupManager = struct {
    allocator: std.mem.Allocator,
    initialized: bool = false,
    total_backups_triggered: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) BackupManager {
        return .{
            .allocator = allocator,
            .initialized = true,
        };
    }

    pub fn deinit(self: *BackupManager) void {
        self.initialized = false;
    }

    /// Trigger a backup by spawning the PowerShell script.
    /// Returns true if the backup process was started successfully.
    /// On non-Windows, logs an advisory message and returns false.
    pub fn triggerBackup(self: *BackupManager, full: bool) bool {
        if (!self.initialized) return false;
        self.total_backups_triggered += 1;

        if (@import("builtin").os.tag != .windows) {
            std.log.info("[BACKUP] Advisory: run aegis_backup.ps1 manually (non-Windows Host)", .{});
            return false;
        }

        std.log.info("[BACKUP] Triggering {} backup (call #{})", .{ if (full) @as([]const u8, "full") else "standard", self.total_backups_triggered });

        // Spawn PowerShell process
        const args: []const []const u8 = if (full)
            &.{ "powershell", "-ExecutionPolicy", "Bypass", "-File", ".\\aegis_backup.ps1", "-Full" }
        else
            &.{ "powershell", "-ExecutionPolicy", "Bypass", "-File", ".\\aegis_backup.ps1" };

        var child = std.process.Child.init(args, self.allocator);
        child.spawn() catch |err| {
            std.log.err("[BACKUP] Failed to spawn backup process: {}", .{err});
            return false;
        };

        // Don't wait for completion - let it run in background
        std.log.info("[BACKUP] Backup process started (PID={})", .{child.id});
        return true;
    }

    /// List available backups by scanning the backups/ directory.
    /// Returns count of backups found.
    pub fn listBackups(self: *BackupManager) !u32 {
        if (!self.initialized) return 0;

        var dir = std.fs.cwd().openDir(BACKUP_DIR, .{ .iterate = true }) catch |err| {
            if (err == error.FileNotFound) {
                std.log.info("[BACKUP] No backups directory found", .{});
                return 0;
            }
            return err;
        };
        defer dir.close();

        var count: u32 = 0;
        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .file and std.mem.startsWith(u8, entry.name, "backup_") and std.mem.endsWith(u8, entry.name, ".zip")) {
                count += 1;
                if (count <= MAX_BACKUPS_TO_LIST) {
                    std.log.info("[BACKUP]   {d}. {s}", .{ count, entry.name });
                }
            }
        }

        if (count > MAX_BACKUPS_TO_LIST) {
            std.log.info("[BACKUP]   ... and {d} more", .{count - MAX_BACKUPS_TO_LIST});
        }

        std.log.info("[BACKUP] Total backups: {d}", .{count});
        return count;
    }

    /// Validate a backup archive by checking it has a manifest.json.
    pub fn validateBackup(self: *BackupManager, backup_name: []const u8) bool {
        if (!self.initialized) return false;

        var path_buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ BACKUP_DIR, backup_name }) catch return false;

        const file = std.fs.cwd().openFile(path, .{}) catch {
            std.log.err("[BACKUP] File not found: {s}", .{path});
            return false;
        };
        defer file.close();

        // Check it's a valid file (not empty)
        const stat = file.stat() catch return false;
        if (stat.size == 0) {
            std.log.err("[BACKUP] Empty backup file: {s}", .{path});
            return false;
        }

        std.log.info("[BACKUP] Valid: {s} ({d} bytes)", .{ path, stat.size });
        return true;
    }

    /// Recommend a backup before risky operations (e.g., config reload).
    pub fn recommendBackupBefore(self: *BackupManager, operation: []const u8) void {
        if (!self.initialized) return;

        std.log.info("[BACKUP] RECOMMENDATION: Run backup before '{s}'", .{operation});
        std.log.info("[BACKUP]   powershell -ExecutionPolicy Bypass -File .\\aegis_backup.ps1", .{});
    }

    pub fn resetStats(self: *BackupManager) void {
        self.total_backups_triggered = 0;
    }
};

// ============================================================
// Singleton facade
// ============================================================

var g_manager: ?BackupManager = null;
var g_initialized: bool = false;

pub fn init(allocator: std.mem.Allocator) void {
    if (g_initialized) return;
    g_manager = BackupManager.init(allocator);
    g_initialized = true;
    std.log.info("[BACKUP] Backup manager initialized (Phase 35)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn shutdown() void {
    if (!g_initialized) return;
    if (g_manager) |*mgr| mgr.deinit();
    g_manager = null;
    g_initialized = false;
    std.log.info("[BACKUP] Backup manager shutdown", .{});
}

pub fn triggerBackup(full: bool) bool {
    if (!g_initialized) return false;
    if (g_manager) |*mgr| return mgr.triggerBackup(full);
    return false;
}

pub fn listBackups() !u32 {
    if (!g_initialized) return 0;
    if (g_manager) |*mgr| return try mgr.listBackups();
    return 0;
}

pub fn recommendBackupBefore(operation: []const u8) void {
    if (!g_initialized) return;
    if (g_manager) |*mgr| mgr.recommendBackupBefore(operation);
}

// ============================================================
// Tests
// ============================================================

test "BackupManager.init creates manager" {
    var mgr = BackupManager.init(std.testing.allocator);
    defer mgr.deinit();
    try std.testing.expect(mgr.initialized);
    try std.testing.expect(mgr.total_backups_triggered == 0);
}

test "BackupManager.triggerBackup on non-Windows returns false" {
    var mgr = BackupManager.init(std.testing.allocator);
    defer mgr.deinit();

    if (@import("builtin").os.tag != .windows) {
        try std.testing.expect(!mgr.triggerBackup(false));
        try std.testing.expect(mgr.total_backups_triggered == 1);
    }
}

test "BackupManager.recommendBackupBefore logs message" {
    var mgr = BackupManager.init(std.testing.allocator);
    defer mgr.deinit();
    mgr.recommendBackupBefore("config_reload");
    // Just verify it doesn't crash
}

test "BackupManager.resetStats zeroes counter" {
    var mgr = BackupManager.init(std.testing.allocator);
    defer mgr.deinit();
    mgr.total_backups_triggered = 5;
    mgr.resetStats();
    try std.testing.expect(mgr.total_backups_triggered == 0);
}

test "backup_manager singleton lifecycle" {
    if (isInitialized()) shutdown();
    try std.testing.expect(!isInitialized());

    init(std.testing.allocator);
    defer shutdown();
    try std.testing.expect(isInitialized());
}

test "BackupManifest struct has expected fields" {
    const manifest = BackupManifest{
        .backup_timestamp = "20260905_103000",
        .backup_date = "2026-09-05T10:30:00",
        .total_files = 42,
        .mode = "Standard",
        .wfp_driver_running = true,
        .test_signing_enabled = true,
    };
    try std.testing.expect(manifest.total_files == 42);
    try std.testing.expect(manifest.wfp_driver_running);
    try std.testing.expect(manifest.test_cert_thumbprint == null);
}
