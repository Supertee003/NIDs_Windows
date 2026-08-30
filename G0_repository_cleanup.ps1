# ============================================================
# AEGIS NIDS - G0: Repository Consolidation (v5.0 Section 4)
# ============================================================
# Cleans repository of:
#   - 44 backup_phase*/backup_hotfix*/backup_pre_rewrite directories
#   - .zig-cache (committed despite .gitignore)
#   - Compiled .pyd binary
#   - release/ directory (zip artifacts)
#   - obj*/objc* build log dirs under drivers/
#   - Stray .zig files at root
#   - Duplicate rules.json at root
#   - logs/ runtime logs
#   - .orphan files
#
# Updates .gitignore to prevent recurrence.
# ============================================================
$ErrorActionPreference = 'Continue'
$RepoRoot = $PSScriptRoot
if (-not $RepoRoot) { $RepoRoot = (Get-Location).Path }

Write-Host "[G0] Repository Consolidation - Starting cleanup..."
Write-Host ""

# Track what we remove
$removedDirs = 0
$removedFiles = 0
$freedBytes = 0

function Remove-ItemSafe {
    param([string]$Path, [string]$Type = "item")
    if (Test-Path $Path) {
        $size = 0
        if (Test-Path $Path -PathType Container) {
            $size = (Get-ChildItem $Path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        } else {
            $size = (Get-Item $Path).Length
        }
        Remove-Item $Path -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $Path)) {
            Write-Host ("  [REMOVED] " + $Path + " (" + [math]::Round($size / 1KB, 1) + " KB)")
            $script:removedDirs += if ($Type -eq "dir") { 1 } else { 0 }
            $script:removedFiles += if ($Type -eq "file") { 1 } else { 0 }
            $script:freedBytes += $size
        } else {
            Write-Host ("  [SKIP] Could not remove: " + $Path) -ForegroundColor Yellow
        }
    }
}

# ============================================================
# 1. Remove backup_phase*, backup_hotfix*, backup_pre_rewrite
# ============================================================
Write-Host "[G0.1] Removing backup directories..."
Get-ChildItem $RepoRoot -Directory | Where-Object {
    $_.Name -match '^backup_phase\d+' -or
    $_.Name -match '^backup_hotfix' -or
    $_.Name -match '^backup_pre_rewrite'
} | ForEach-Object {
    Remove-ItemSafe $_.FullName "dir"
}
Write-Host ""

# ============================================================
# 2. Remove .zig-cache
# ============================================================
Write-Host "[G0.2] Removing .zig-cache..."
Remove-ItemSafe (Join-Path $RepoRoot ".zig-cache") "dir"
Write-Host ""

# ============================================================
# 3. Remove compiled binaries
# ============================================================
Write-Host "[G0.3] Removing compiled binaries..."
# .pyd files
Get-ChildItem $RepoRoot -Recurse -Filter "*.pyd" -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-ItemSafe $_.FullName "file"
}
# .obj, .o, .pdb, .lib, .exp, .sys (if any tracked)
Get-ChildItem $RepoRoot -Recurse -Include "*.obj","*.o","*.pdb","*.lib","*.exp","*.sys" -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-ItemSafe $_.FullName "file"
}
Write-Host ""

# ============================================================
# 4. Remove release/ directory (artifacts)
# ============================================================
Write-Host "[G0.4] Removing release/ directory..."
Remove-ItemSafe (Join-Path $RepoRoot "release") "dir"
Write-Host ""

# ============================================================
# 5. Remove obj*/objc* build log dirs under drivers/
# ============================================================
Write-Host "[G0.5] Removing build log directories under drivers/..."
$driversPath = Join-Path $RepoRoot "drivers"
if (Test-Path $driversPath) {
    Get-ChildItem $driversPath -Recurse -Directory | Where-Object {
        $_.Name -match '^obj\w*$'
    } | ForEach-Object {
        Remove-ItemSafe $_.FullName "dir"
    }
}
Write-Host ""

# ============================================================
# 6. Remove stray .zig files at root
# ============================================================
Write-Host "[G0.6] Removing stray .zig files at root..."
$strayZig = @(
    "canonical_event.zig",
    "event_fabric.zig",
    "nose_contract.zig"
)
foreach ($file in $strayZig) {
    $fullPath = Join-Path $RepoRoot $file
    if (Test-Path $fullPath) {
        # Check if same file exists in core/ before removing
        $corePath = Join-Path $RepoRoot ("core\" + $file)
        if (Test-Path $corePath) {
            Remove-ItemSafe $fullPath "file"
        } else {
            Write-Host ("  [KEEP] " + $file + " (no duplicate in core/)") -ForegroundColor Yellow
        }
    }
}
Write-Host ""

# ============================================================
# 7. Remove duplicate rules.json at root (keep config/Rules.json)
# ============================================================
Write-Host "[G0.7] Checking duplicate rules.json..."
$rootRules = Join-Path $RepoRoot "rules.json"
$configRules = Join-Path $RepoRoot "config\Rules.json"
if ((Test-Path $rootRules) -and (Test-Path $configRules)) {
    $rootHash = (Get-FileHash $rootRules -Algorithm SHA256).Hash
    $configHash = (Get-FileHash $configRules -Algorithm SHA256).Hash
    if ($rootHash -eq $configHash) {
        Remove-ItemSafe $rootRules "file"
    } else {
        Write-Host "  [WARN] rules.json differs from config/Rules.json - keeping both" -ForegroundColor Yellow
    }
}
Write-Host ""

# ============================================================
# 8. Remove logs/ runtime logs
# ============================================================
Write-Host "[G0.8] Removing runtime logs..."
$logsPath = Join-Path $RepoRoot "logs"
if (Test-Path $logsPath) {
    Get-ChildItem $logsPath -Recurse -Include "*.log","*.ndjson","*.json" -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-ItemSafe $_.FullName "file"
    }
    # Remove pids directory if exists
    $pidsPath = Join-Path $logsPath "pids"
    if (Test-Path $pidsPath) {
        Remove-ItemSafe $pidsPath "dir"
    }
}
Write-Host ""

# ============================================================
# 9. Remove .orphan files
# ============================================================
Write-Host "[G0.9] Removing .orphan files..."
Get-ChildItem $RepoRoot -Recurse -Filter "*.orphan" -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-ItemSafe $_.FullName "file"
}
Write-Host ""

# ============================================================
# 10. Remove .vscode (IDE config)
# ============================================================
Write-Host "[G0.10] Removing .vscode/..."
Remove-ItemSafe (Join-Path $RepoRoot ".vscode") "dir"
Write-Host ""

# ============================================================
# 11. Update .gitignore
# ============================================================
Write-Host "[G0.11] Updating .gitignore..."
$gitignorePath = Join-Path $RepoRoot ".gitignore"
$additionalRules = @(
    "",
    "# G0: Repository Consolidation additions",
    "backup_phase*/",
    "backup_hotfix*/",
    "backup_pre_rewrite/",
    ".zig-cache/",
    "*.pyd",
    "release/",
    "obj*/",
    "objc*/",
    "*.orphan",
    ".vscode/",
    "logs/*.ndjson",
    "logs/*.json",
    "logs/pids/",
    "phase*_*.ps1"
)

$existingContent = ""
if (Test-Path $gitignorePath) {
    $existingContent = Get-Content $gitignorePath -Raw
}

# Only add rules that don't already exist
$newRules = @()
foreach ($rule in $additionalRules) {
    if ($rule -eq "" -or $existingContent -notmatch [regex]::Escape($rule.TrimEnd('/'))) {
        $newRules += $rule
    }
}

if ($newRules.Count -gt 0) {
    Add-Content $gitignorePath "`n# --- G0 additions ---"
    foreach ($rule in $newRules) {
        if ($rule -ne "") {
            Add-Content $gitignorePath $rule
        }
    }
    Write-Host ("  [UPDATED] .gitignore (+ " + $newRules.Count + " rules)")
} else {
    Write-Host "  [OK] .gitignore already has all rules"
}
Write-Host ""

# ============================================================
# 12. Remove deploy scripts from root (they are in download/ on dev machine)
# ============================================================
Write-Host "[G0.12] Removing deploy scripts from repo root..."
Get-ChildItem $RepoRoot -Filter "phase*.ps1" -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-ItemSafe $_.FullName "file"
}
Get-ChildItem $RepoRoot -Filter "generate_deploy_script.py" -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-ItemSafe $_.FullName "file"
}
Write-Host ""

# ============================================================
# Summary
# ============================================================
Write-Host ""
Write-Host "============================================================"
Write-Host "  G0 Repository Consolidation Complete"
Write-Host "============================================================"
Write-Host ("  Directories removed: " + $removedDirs)
Write-Host ("  Files removed: " + $removedFiles)
Write-Host ("  Space freed: " + [math]::Round($freedBytes / 1MB, 2) + " MB")
Write-Host ""
Write-Host "  Next steps:"
Write-Host "    1. git add -A"
Write-Host "    2. git commit -m 'G0: repository consolidation - remove backups, cache, artifacts'"
Write-Host "    3. git push"
Write-Host "    4. Verify: git clone -> clean source tree -> zig build test"
Write-Host ""
Write-Host "  G0 Exit Gate:"
Write-Host "    git clone -> clean source tree -> build from scratch"
Write-Host "============================================================"
