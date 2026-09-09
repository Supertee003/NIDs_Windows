// PATCH-45 - Installer / Upgrade / Recovery
// AEGIS NIDS v5.0+ -- Installation, upgrade, and recovery procedures
//
// This module defines the installer manifest, upgrade path, and
// recovery procedures for the AEGIS system.

const std = @import("std");

// ============================================================================
// Installer Manifest
// ============================================================================

pub const InstallerManifest = struct {
    product_name: [64]u8,
    product_version: [32]u8,
    min_os_version: [32]u8,
    required_disk_mb: u32,
    required_ram_mb: u32,
    required_cpu_cores: u32,
    install_path: [256]u8,
    services: [8]ServiceInfo,
    service_count: u32,
    drivers: [4]DriverInfo,
    driver_count: u32,

    pub const ServiceInfo = struct {
        name: [64]u8,
        display_name: [128]u8,
        start_type: u8, // 0=auto, 1=demand, 2=disabled
        binary_path: [256]u8,
    };

    pub const DriverInfo = struct {
        name: [64]u8,
        binary_path: [256]u8,
        service_type: u8, // 0=kernel, 1=filesystem, 2=network
    };

    pub fn init() InstallerManifest {
        return .{
            .product_name = [_]u8{0} ** 64,
            .product_version = [_]u8{0} ** 32,
            .min_os_version = [_]u8{0} ** 32,
            .required_disk_mb = 0,
            .required_ram_mb = 0,
            .required_cpu_cores = 0,
            .install_path = [_]u8{0} ** 256,
            .services = [_]ServiceInfo{std.mem.zeroes(ServiceInfo)} ** 8,
            .service_count = 0,
            .drivers = [_]DriverInfo{std.mem.zeroes(DriverInfo)} ** 4,
            .driver_count = 0,
        };
    }

    pub fn setProductName(self: *InstallerManifest, name: []const u8) void {
        const len = @min(name.len, 63);
        @memcpy(self.product_name[0..len], name[0..len]);
    }

    pub fn setProductVersion(self: *InstallerManifest, version: []const u8) void {
        const len = @min(version.len, 31);
        @memcpy(self.product_version[0..len], version[0..len]);
    }

    pub fn setInstallPath(self: *InstallerManifest, path: []const u8) void {
        const len = @min(path.len, 255);
        @memcpy(self.install_path[0..len], path[0..len]);
    }

    pub fn addService(self: *InstallerManifest, name: []const u8, display: []const u8, start: u8, path: []const u8) bool {
        if (self.service_count >= 8) return false;
        const idx = self.service_count;
        const name_len = @min(name.len, 63);
        @memcpy(self.services[idx].name[0..name_len], name[0..name_len]);
        const display_len = @min(display.len, 127);
        @memcpy(self.services[idx].display_name[0..display_len], display[0..display_len]);
        self.services[idx].start_type = start;
        const path_len = @min(path.len, 255);
        @memcpy(self.services[idx].binary_path[0..path_len], path[0..path_len]);
        self.service_count += 1;
        return true;
    }

    pub fn addDriver(self: *InstallerManifest, name: []const u8, path: []const u8, stype: u8) bool {
        if (self.driver_count >= 4) return false;
        const idx = self.driver_count;
        const name_len = @min(name.len, 63);
        @memcpy(self.drivers[idx].name[0..name_len], name[0..name_len]);
        const path_len = @min(path.len, 255);
        @memcpy(self.drivers[idx].binary_path[0..path_len], path[0..path_len]);
        self.drivers[idx].service_type = stype;
        self.driver_count += 1;
        return true;
    }

    pub fn verifyIntegrity(self: *const InstallerManifest) bool {
        if (self.service_count > 8) return false;
        if (self.driver_count > 4) return false;
        // Verify product name is set
        var name_set = false;
        for (self.product_name) |b| {
            if (b != 0) {
                name_set = true;
                break;
            }
        }
        if (!name_set) return false;
        return true;
    }
};

// ============================================================================
// Upgrade Path
// ============================================================================

pub const UpgradePath = struct {
    from_version: [32]u8,
    to_version: [32]u8,
    upgrade_type: u8, // 0=in-place, 1=migration, 2=fresh install
    requires_reboot: bool,
    backup_required: bool,
    migration_steps: [8]MigrationStep,
    step_count: u32,

    pub const MigrationStep = struct {
        name: [64]u8,
        description: [256]u8,
        order: u32,
    };

    pub fn init() UpgradePath {
        return .{
            .from_version = [_]u8{0} ** 32,
            .to_version = [_]u8{0} ** 32,
            .upgrade_type = 0,
            .requires_reboot = false,
            .backup_required = false,
            .migration_steps = [_]MigrationStep{std.mem.zeroes(MigrationStep)} ** 8,
            .step_count = 0,
        };
    }

    pub fn addMigrationStep(self: *UpgradePath, name: []const u8, desc: []const u8, order: u32) bool {
        if (self.step_count >= 8) return false;
        const idx = self.step_count;
        const name_len = @min(name.len, 63);
        @memcpy(self.migration_steps[idx].name[0..name_len], name[0..name_len]);
        const desc_len = @min(desc.len, 255);
        @memcpy(self.migration_steps[idx].description[0..desc_len], desc[0..desc_len]);
        self.migration_steps[idx].order = order;
        self.step_count += 1;
        return true;
    }

    pub fn isSafeUpgrade(self: *const UpgradePath) bool {
        // Safe upgrade: no reboot required, backup not required
        return !self.requires_reboot and !self.backup_required;
    }
};

// ============================================================================
// Recovery Procedures
// ============================================================================

pub const RecoveryProcedure = struct {
    name: [64]u8,
    description: [256]u8,
    priority: u8, // 0=critical, 1=high, 2=medium, 3=low
    estimated_time_sec: u32,
    requires_admin: bool,
    steps: [8]RecoveryStep,
    step_count: u32,

    pub const RecoveryStep = struct {
        name: [64]u8,
        action: [256]u8,
        order: u32,
    };

    pub fn init() RecoveryProcedure {
        return .{
            .name = [_]u8{0} ** 64,
            .description = [_]u8{0} ** 256,
            .priority = 3,
            .estimated_time_sec = 0,
            .requires_admin = false,
            .steps = [_]RecoveryStep{std.mem.zeroes(RecoveryStep)} ** 8,
            .step_count = 0,
        };
    }

    pub fn addStep(self: *RecoveryProcedure, name: []const u8, action: []const u8, order: u32) bool {
        if (self.step_count >= 8) return false;
        const idx = self.step_count;
        const name_len = @min(name.len, 63);
        @memcpy(self.steps[idx].name[0..name_len], name[0..name_len]);
        const action_len = @min(action.len, 255);
        @memcpy(self.steps[idx].action[0..action_len], action[0..action_len]);
        self.steps[idx].order = order;
        self.step_count += 1;
        return true;
    }

    pub fn isCritical(self: *const RecoveryProcedure) bool {
        return self.priority == 0;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "InstallerManifest init" {
    const manifest = InstallerManifest.init();
    try std.testing.expectEqual(@as(u32, 0), manifest.service_count);
    try std.testing.expectEqual(@as(u32, 0), manifest.driver_count);
}

test "InstallerManifest setProductName" {
    var manifest = InstallerManifest.init();
    manifest.setProductName("AEGIS NIDS");
    try std.testing.expectEqual(@as(u8, 'A'), manifest.product_name[0]);
    try std.testing.expectEqual(@as(u8, 'E'), manifest.product_name[1]);
}

test "InstallerManifest addService" {
    var manifest = InstallerManifest.init();
    const added = manifest.addService("aegis_core", "AEGIS Core Service", 0, "C:\\aegis\\core.exe");
    try std.testing.expect(added);
    try std.testing.expectEqual(@as(u32, 1), manifest.service_count);
}

test "InstallerManifest addService overflow" {
    var manifest = InstallerManifest.init();
    var i: u32 = 0;
    while (i < 9) : (i += 1) {
        _ = manifest.addService("svc", "Service", 0, "path");
    }
    try std.testing.expectEqual(@as(u32, 8), manifest.service_count);
}

test "InstallerManifest addDriver" {
    var manifest = InstallerManifest.init();
    const added = manifest.addDriver("aegis_wfp", "C:\\aegis\\wfp.sys", 2);
    try std.testing.expect(added);
    try std.testing.expectEqual(@as(u32, 1), manifest.driver_count);
}

test "InstallerManifest verifyIntegrity" {
    var manifest = InstallerManifest.init();
    manifest.setProductName("AEGIS");
    try std.testing.expect(manifest.verifyIntegrity());
}

test "UpgradePath init" {
    const path = UpgradePath.init();
    try std.testing.expectEqual(@as(u32, 0), path.step_count);
    try std.testing.expect(path.isSafeUpgrade());
}

test "UpgradePath addMigrationStep" {
    var path = UpgradePath.init();
    const added = path.addMigrationStep("backup_db", "Backup database", 1);
    try std.testing.expect(added);
    try std.testing.expectEqual(@as(u32, 1), path.step_count);
}

test "UpgradePath requires reboot" {
    var path = UpgradePath.init();
    path.requires_reboot = true;
    try std.testing.expect(!path.isSafeUpgrade());
}

test "RecoveryProcedure init" {
    const proc = RecoveryProcedure.init();
    try std.testing.expectEqual(@as(u32, 0), proc.step_count);
    try std.testing.expect(!proc.isCritical());
}

test "RecoveryProcedure addStep" {
    var proc = RecoveryProcedure.init();
    const added = proc.addStep("stop_service", "Stop AEGIS service", 1);
    try std.testing.expect(added);
    try std.testing.expectEqual(@as(u32, 1), proc.step_count);
}

test "RecoveryProcedure isCritical" {
    var proc = RecoveryProcedure.init();
    proc.priority = 0;
    try std.testing.expect(proc.isCritical());
}

// ============================================================================
// REL-002: Installer Integrity Comprehensive Tests
// ============================================================================

test "REL-002: InstallerManifest empty not integrity" {
    const manifest = InstallerManifest.init();
    try std.testing.expect(!manifest.verifyIntegrity());
}

test "REL-002: InstallerManifest product name only = integrity" {
    var manifest = InstallerManifest.init();
    manifest.setProductName("AEGIS NIDS");
    try std.testing.expect(manifest.verifyIntegrity());
}

test "REL-002: InstallerManifest addService up to 8" {
    var manifest = InstallerManifest.init();
    manifest.setProductName("AEGIS");
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        const added = manifest.addService("svc", "Service", 0, "path");
        try std.testing.expect(added);
    }
    try std.testing.expectEqual(@as(u32, 8), manifest.service_count);
    // 9th should fail
    try std.testing.expect(!manifest.addService("extra", "Extra", 0, "path"));
}

test "REL-002: InstallerManifest addDriver up to 4" {
    var manifest = InstallerManifest.init();
    manifest.setProductName("AEGIS");
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        const added = manifest.addDriver("drv", "path", 1);
        try std.testing.expect(added);
    }
    try std.testing.expectEqual(@as(u32, 4), manifest.driver_count);
    // 5th should fail
    try std.testing.expect(!manifest.addDriver("extra", "path", 1));
}

test "REL-002: InstallerManifest service fields stored correctly" {
    var manifest = InstallerManifest.init();
    manifest.setProductName("AEGIS");
    _ = manifest.addService("aegis_svc", "AEGIS Service", 2, "C:\\aegis\\svc.exe");
    try std.testing.expectEqual(@as(u32, 1), manifest.service_count);
    try std.testing.expectEqual(@as(u8, 'a'), manifest.services[0].name[0]);
}

test "REL-002: InstallerManifest driver fields stored correctly" {
    var manifest = InstallerManifest.init();
    manifest.setProductName("AEGIS");
    _ = manifest.addDriver("aegis_wfp", "C:\\aegis\\wfp.sys", 3);
    try std.testing.expectEqual(@as(u32, 1), manifest.driver_count);
    try std.testing.expectEqual(@as(u8, 3), manifest.drivers[0].service_type);
}

test "REL-002: UpgradePath empty is safe" {
    const path = UpgradePath.init();
    try std.testing.expect(path.isSafeUpgrade());
    try std.testing.expectEqual(@as(u32, 0), path.step_count);
}

test "REL-002: UpgradePath with steps is safe" {
    var path = UpgradePath.init();
    _ = path.addMigrationStep("step1", "Step 1", 1);
    _ = path.addMigrationStep("step2", "Step 2", 2);
    try std.testing.expect(path.isSafeUpgrade());
    try std.testing.expectEqual(@as(u32, 2), path.step_count);
}

test "REL-002: UpgradePath with reboot not safe" {
    var path = UpgradePath.init();
    _ = path.addMigrationStep("step1", "Step 1", 1);
    path.requires_reboot = true;
    try std.testing.expect(!path.isSafeUpgrade());
}

test "REL-002: UpgradePath step fields stored correctly" {
    var path = UpgradePath.init();
    _ = path.addMigrationStep("backup", "Backup database", 5);
    try std.testing.expectEqual(@as(u32, 1), path.step_count);
    try std.testing.expectEqual(@as(u32, 5), path.migration_steps[0].order);
}

test "REL-002: RecoveryProcedure empty not critical" {
    const proc = RecoveryProcedure.init();
    try std.testing.expect(!proc.isCritical());
    try std.testing.expectEqual(@as(u32, 0), proc.step_count);
}

test "REL-002: RecoveryProcedure priority 0 is critical" {
    var proc = RecoveryProcedure.init();
    proc.priority = 0;
    try std.testing.expect(proc.isCritical());
}

test "REL-002: RecoveryProcedure priority 1 not critical" {
    var proc = RecoveryProcedure.init();
    proc.priority = 1;
    try std.testing.expect(!proc.isCritical());
}

test "REL-002: RecoveryProcedure addStep up to 8" {
    var proc = RecoveryProcedure.init();
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        const added = proc.addStep("step", "Step", 1);
        try std.testing.expect(added);
    }
    try std.testing.expectEqual(@as(u32, 8), proc.step_count);
    // 9th should fail
    try std.testing.expect(!proc.addStep("extra", "Extra", 1));
}

test "REL-002: RecoveryProcedure step fields stored correctly" {
    var proc = RecoveryProcedure.init();
    _ = proc.addStep("stop_svc", "Stop service", 3);
    try std.testing.expectEqual(@as(u32, 1), proc.step_count);
    try std.testing.expectEqual(@as(u32, 3), proc.steps[0].order);
}

// ============================================================================
// REL-003: Upgrade Path Comprehensive Tests
// ============================================================================

test "REL-003: UpgradePath default is safe in-place upgrade" {
    const path = UpgradePath.init();
    try std.testing.expect(path.isSafeUpgrade());
    try std.testing.expectEqual(@as(u8, 0), path.upgrade_type);
    try std.testing.expect(!path.requires_reboot);
    try std.testing.expect(!path.backup_required);
}

test "REL-003: UpgradePath in-place upgrade (type 0)" {
    var path = UpgradePath.init();
    path.upgrade_type = 0;
    @memcpy(path.from_version[0..5], "4.0.0");
    @memcpy(path.to_version[0..5], "5.0.0");
    try std.testing.expect(path.isSafeUpgrade());
}

test "REL-003: UpgradePath migration upgrade (type 1)" {
    var path = UpgradePath.init();
    path.upgrade_type = 1;
    @memcpy(path.from_version[0..5], "3.0.0");
    @memcpy(path.to_version[0..5], "5.0.0");
    path.backup_required = true;
    try std.testing.expect(!path.isSafeUpgrade());
}

test "REL-003: UpgradePath fresh install (type 2)" {
    var path = UpgradePath.init();
    path.upgrade_type = 2;
    @memcpy(path.to_version[0..5], "5.0.0");
    try std.testing.expect(path.isSafeUpgrade());
}

test "REL-003: UpgradePath addMigrationStep up to 8" {
    var path = UpgradePath.init();
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        const added = path.addMigrationStep("step", "Step", i);
        try std.testing.expect(added);
    }
    try std.testing.expectEqual(@as(u32, 8), path.step_count);
    // 9th should fail
    try std.testing.expect(!path.addMigrationStep("extra", "Extra", 8));
}

test "REL-003: UpgradePath migration steps ordered correctly" {
    var path = UpgradePath.init();
    _ = path.addMigrationStep("backup", "Backup database", 1);
    _ = path.addMigrationStep("migrate", "Migrate schema", 2);
    _ = path.addMigrationStep("verify", "Verify integrity", 3);
    try std.testing.expectEqual(@as(u32, 3), path.step_count);
    try std.testing.expectEqual(@as(u32, 1), path.migration_steps[0].order);
    try std.testing.expectEqual(@as(u32, 2), path.migration_steps[1].order);
    try std.testing.expectEqual(@as(u32, 3), path.migration_steps[2].order);
}

test "REL-003: UpgradePath with reboot not safe" {
    var path = UpgradePath.init();
    path.requires_reboot = true;
    try std.testing.expect(!path.isSafeUpgrade());
}

test "REL-003: UpgradePath with backup required not safe" {
    var path = UpgradePath.init();
    path.backup_required = true;
    try std.testing.expect(!path.isSafeUpgrade());
}

test "REL-003: UpgradePath with reboot and backup not safe" {
    var path = UpgradePath.init();
    path.requires_reboot = true;
    path.backup_required = true;
    try std.testing.expect(!path.isSafeUpgrade());
}

test "REL-003: UpgradePath version fields stored correctly" {
    var path = UpgradePath.init();
    @memcpy(path.from_version[0..5], "4.2.1");
    @memcpy(path.to_version[0..5], "5.0.0");
    try std.testing.expectEqual(@as(u8, '4'), path.from_version[0]);
    try std.testing.expectEqual(@as(u8, '.'), path.from_version[1]);
    try std.testing.expectEqual(@as(u8, '5'), path.to_version[0]);
}

test "REL-003: UpgradePath migration step description stored correctly" {
    var path = UpgradePath.init();
    _ = path.addMigrationStep("migrate_db", "Migrate database schema from v4 to v5", 1);
    try std.testing.expectEqual(@as(u8, 'M'), path.migration_steps[0].description[0]);
    try std.testing.expectEqual(@as(u8, 'i'), path.migration_steps[0].description[1]);
}

test "REL-003: UpgradePath empty steps count is 0" {
    const path = UpgradePath.init();
    try std.testing.expectEqual(@as(u32, 0), path.step_count);
}

// ============================================================================
// REL-004: Recovery Procedures Comprehensive Tests
// ============================================================================

test "REL-004: RecoveryProcedure default is low priority" {
    const proc = RecoveryProcedure.init();
    try std.testing.expectEqual(@as(u8, 3), proc.priority);
    try std.testing.expect(!proc.isCritical());
}

test "REL-004: RecoveryProcedure critical priority (0)" {
    var proc = RecoveryProcedure.init();
    proc.priority = 0;
    try std.testing.expect(proc.isCritical());
}

test "REL-004: RecoveryProcedure high priority (1)" {
    var proc = RecoveryProcedure.init();
    proc.priority = 1;
    try std.testing.expect(!proc.isCritical());
}

test "REL-004: RecoveryProcedure medium priority (2)" {
    var proc = RecoveryProcedure.init();
    proc.priority = 2;
    try std.testing.expect(!proc.isCritical());
}

test "REL-004: RecoveryProcedure low priority (3)" {
    var proc = RecoveryProcedure.init();
    proc.priority = 3;
    try std.testing.expect(!proc.isCritical());
}

test "REL-004: RecoveryProcedure addStep up to 8" {
    var proc = RecoveryProcedure.init();
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        const added = proc.addStep("step", "Action", i);
        try std.testing.expect(added);
    }
    try std.testing.expectEqual(@as(u32, 8), proc.step_count);
    // 9th should fail
    try std.testing.expect(!proc.addStep("extra", "Extra", 8));
}

test "REL-004: RecoveryProcedure steps ordered correctly" {
    var proc = RecoveryProcedure.init();
    _ = proc.addStep("stop_svc", "Stop service", 1);
    _ = proc.addStep("backup_db", "Backup database", 2);
    _ = proc.addStep("restore", "Restore from backup", 3);
    try std.testing.expectEqual(@as(u32, 3), proc.step_count);
    try std.testing.expectEqual(@as(u32, 1), proc.steps[0].order);
    try std.testing.expectEqual(@as(u32, 2), proc.steps[1].order);
    try std.testing.expectEqual(@as(u32, 3), proc.steps[2].order);
}

test "REL-004: RecoveryProcedure requires_admin flag" {
    var proc = RecoveryProcedure.init();
    try std.testing.expect(!proc.requires_admin);
    proc.requires_admin = true;
    try std.testing.expect(proc.requires_admin);
}

test "REL-004: RecoveryProcedure estimated_time_sec" {
    var proc = RecoveryProcedure.init();
    try std.testing.expectEqual(@as(u32, 0), proc.estimated_time_sec);
    proc.estimated_time_sec = 300;
    try std.testing.expectEqual(@as(u32, 300), proc.estimated_time_sec);
}

test "REL-004: RecoveryProcedure step name stored correctly" {
    var proc = RecoveryProcedure.init();
    _ = proc.addStep("stop_aegis", "Stop AEGIS service", 1);
    try std.testing.expectEqual(@as(u8, 's'), proc.steps[0].name[0]);
    try std.testing.expectEqual(@as(u8, 't'), proc.steps[0].name[1]);
    try std.testing.expectEqual(@as(u8, 'o'), proc.steps[0].name[2]);
}

test "REL-004: RecoveryProcedure step action stored correctly" {
    var proc = RecoveryProcedure.init();
    _ = proc.addStep("stop", "net stop aegis_core", 1);
    try std.testing.expectEqual(@as(u8, 'n'), proc.steps[0].action[0]);
    try std.testing.expectEqual(@as(u8, 'e'), proc.steps[0].action[1]);
    try std.testing.expectEqual(@as(u8, 't'), proc.steps[0].action[2]);
}

test "REL-004: RecoveryProcedure empty step count is 0" {
    const proc = RecoveryProcedure.init();
    try std.testing.expectEqual(@as(u32, 0), proc.step_count);
}
