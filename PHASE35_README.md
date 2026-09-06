# AEGIS NIDS - Phase 35: Backup & Recovery

## Overview
Safety net for all future phases. Backs up + restores all AEGIS NIDS state.
Zero risk to running system (read-only operations during backup).

## Risk Level: LOW
- **Scripts only** — no code changes to running NIDS
- **Read-only during backup** — doesn't modify any files
- **Pre-restore backup** — restore creates a backup BEFORE overwriting
- **Rollback capability** — every restore has a rollback path

## Files Delivered

| File | Type | Purpose |
|------|------|---------|
| `aegis_backup.ps1` | PowerShell | Create timestamped backup archive |
| `aegis_restore.ps1` | PowerShell | Restore from backup (dry run + apply) |
| `phase35_backup_recovery.ps1` | PowerShell | Entry point with help |
| `backup_manager.zig` | Zig | Programmatic API (optional, for lifecycle integration) |
| `PHASE35_README.md` | Markdown | This documentation |

## Quick Start

### 1. Create a Backup (before making changes)
```powershell
powershell -ExecutionPolicy Bypass -File .\aegis_backup.ps1
```

Output:
```
[OK] config/ (5 files)
[OK] core/ (45 files)
[OK] logs/ (3 files, 42 events in anomalous.json)
[OK] WFP driver: RUNNING
[OK] Test signing: ENABLED
[OK] Git commit: a1b2c3d4...
[OK] Archive created: backups\backup_20260905_103000.zip (2.5 MB)

BACKUP COMPLETE
Total files: 53
```

### 2. List Available Backups
```powershell
powershell -ExecutionPolicy Bypass -File .\aegis_restore.ps1 -List
```

Output:
```
Available backups (newest first):

[1] backup_20260905_103000.zip
    Date: 2026-09-05 10:30:00
    Size: 2.5 MB

[2] backup_20260905_090000.zip
    Date: 2026-09-05 09:00:00
    Size: 2.3 MB
```

### 3. Preview a Restore (Dry Run)
```powershell
powershell -ExecutionPolicy Bypass -File .\aegis_restore.ps1 -Backup backups\backup_20260905_103000.zip
```

Output:
```
[DRY RUN] What would be restored:
  [WOULD RESTORE] config/ -> D:\NIDs_Windows\config
  [WOULD RESTORE] core/   -> D:\NIDs_Windows\core
  [WOULD RESTORE] logs/   -> D:\NIDs_Windows\logs
  [WOULD RESTORE] build.zig

To actually restore:
  .\aegis_restore.ps1 -Backup "backups\backup_20260905_103000.zip" -Apply
```

### 4. Actually Restore
```powershell
powershell -ExecutionPolicy Bypass -File .\aegis_restore.ps1 -Backup backups\backup_20260905_103000.zip -Apply
```

The restore script:
1. **Stops AEGIS** (graceful shutdown via stop_aegis.bat)
2. **Creates pre-restore backup** (safety net for rollback)
3. **Restores files** from backup archive
4. **Checks system state** (WFP driver, test signing)
5. **Reports** what was restored + how to rollback

## What Gets Backed Up

### Configuration (`config/`)
- `aegis.conf` — main configuration
- `Rules.json` — detection rules
- `.github/workflows/` — CI configuration

### Engine Source (`core/`)
- All 45+ `.zig` files
- `build.zig` — build configuration
- `scripts/` — launcher scripts

### Forensic Logs (`logs/`)
- `anomalous.json` — detection events (NDJSON)
- `daemon.log` — daemon log
- `core.log` — core engine log
- `brain.log` — Brain log
- `blocked_ips.json` — WFP blocklist

### System State (`system/`)
- WFP driver status (`sc query aegis_wfp`)
- WFP service config (`sc qc aegis_wfp`)
- Test signing mode (`bcdedit`)
- Test certificate thumbprint

### Git State (`git/`)
- Current commit hash
- Working tree status (uncommitted changes)
- Last 20 commits log
- Full `.git/` directory (with `-Full` flag)

## Usage Scenarios

### Before Phase 33 (SIEM Integration)
```powershell
# Backup current state
.\aegis_backup.ps1 -Verify

# Make changes...
# (implement SIEM forwarder)

# If something breaks:
.\aegis_restore.ps1 -Latest -Apply
```

### Before Config Hot-Reload (Phase 34)
```powershell
# Backup config specifically
.\aegis_backup.ps1 -Config

# Modify Rules.json...
# Test hot-reload...

# If rules are bad:
.\aegis_restore.ps1 -Latest -Apply
```

### Scheduled Backups (Task Scheduler)
```powershell
# Create daily backup at 2 AM
schtasks /create /tn "AEGIS_Daily_Backup" /tr "powershell -ExecutionPolicy Bypass -File D:\NIDs_Windows\aegis_backup.ps1" /sc daily /st 02:00 /ru SYSTEM
```

### Pre-Change Backup Hook
Add to any script that modifies AEGIS:
```powershell
# Always backup before changes
& .\aegis_backup.ps1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Backup failed - aborting change" -ForegroundColor Red
    exit 1
}
# Proceed with changes...
```

## Restore Safety Features

1. **Pre-restore backup**: Before restoring, the script creates a backup of the CURRENT state
2. **Logs preserved**: Existing logs are NOT overwritten — backup logs go to `logs/restored_<timestamp>/`
3. **Dry run mode**: Preview what would be restored WITHOUT making changes
4. **Rollback path**: Every restore outputs the command to rollback

## Zig Integration (Optional)

The `backup_manager.zig` module provides a programmatic API:

```zig
const backup = @import("backup_manager.zig");

// Initialize
backup.init(allocator);
defer backup.shutdown();

// Before config reload, recommend backup
backup.recommendBackupBefore("config_reload");

// Trigger backup programmatically
if (backup.triggerBackup(false)) {
    std.log.info("Backup started", .{});
}

// List available backups
const count = try backup.listBackups();
```

## Verification Checklist

- [ ] Backup script runs without errors
- [ ] Archive created in `backups/` directory
- [ ] Manifest.json contains expected metadata
- [ ] Restore dry run shows correct file list
- [ ] Restore -Apply creates pre-restore backup
- [ ] After restore, `zig build test` passes
- [ ] After restore, AEGIS starts (5/5 subsystems)
- [ ] WFP driver still running after restore

## Troubleshooting

### "Backup failed: Access denied"
- Run PowerShell as Administrator
- Check if AEGIS is locking files (stop AEGIS first)

### "Archive creation failed"
- Check disk space: `Get-PSDrive C`
- Try without compression: remove `Compress-Archive` line

### "Restore didn't bring back WFP driver"
- WFP driver is a kernel service — restore doesn't reinstall it
- Run `install_wfp_driver_embedded.ps1` to reinstall driver

### "Git hash mismatch after restore"
- This is expected if you had uncommitted changes
- The backup captured your working tree state, not the committed state
- Use `git stash` or `git checkout` to manage git state separately

## Next Phase

After Phase 35 is verified:
- **Phase 40**: Compliance Reporting (LOW risk, read-only)
- **Phase 33**: SIEM Integration (LOW risk, additive)
