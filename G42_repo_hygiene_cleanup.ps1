# G42 -- Repository Hygiene Cleanup
# ============================================================
# Removes 81 backup files that are still tracked in git
# (they were committed before .gitignore patterns were added).
#
# Also removes the Cython-generated fast_scan.c (463KB).
#
# After running this script, commit the changes:
#   git add -A
#   git commit -m "chore: remove 81 backup files + Cython generated code from git tracking"
#   git push origin main
# ============================================================

$ErrorActionPreference = 'Stop'
$repoRoot = (Get-Location).Path

Write-Host ""
Write-Host "=== AEGIS NIDS - G42 Repository Hygiene Cleanup ===" -ForegroundColor Cyan
Write-Host "Repo root: $repoRoot" -ForegroundColor DarkGray
Write-Host ""

# Step 1: Find and remove all backup files from git tracking
Write-Host "--- Step 1: Remove backup files from git tracking ---" -ForegroundColor Yellow

$backupPatterns = @(
    "*.bak",
    "*.phase*_backup",
    "*_backup",
    "*.phase*backup"
)

$backupFiles = @()
foreach ($pattern in $backupPatterns) {
    $files = git ls-files $pattern 2>$null
    if ($files) {
        $backupFiles += $files
    }
}

# Also find files with "backup" in the name
$allTracked = git ls-files 2>$null
foreach ($f in $allTracked) {
    if ($f -match '\.bak$' -or $f -match '_backup$' -or $f -match '\.phase.*_backup$' -or $f -match 'backup_recovery_proof') {
        if ($backupFiles -notcontains $f) {
            $backupFiles += $f
        }
    }
}

# Remove duplicates
$backupFiles = $backupFiles | Sort-Object -Unique

if ($backupFiles.Count -eq 0) {
    Write-Host "  No backup files found in git tracking." -ForegroundColor Green
} else {
    Write-Host "  Found $($backupFiles.Count) backup files to remove:" -ForegroundColor Yellow
    foreach ($f in $backupFiles) {
        Write-Host "    - $f"
    }
    Write-Host ""

    # Remove each file from git tracking (but keep on disk if desired)
    foreach ($f in $backupFiles) {
        git rm --cached "$f" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    [OK] untracked: $f" -ForegroundColor Green
        } else {
            Write-Host "    [SKIP] could not untrack: $f" -ForegroundColor DarkGray
        }
    }
}

Write-Host ""

# Step 2: Remove Cython-generated fast_scan.c (463KB)
Write-Host "--- Step 2: Remove Cython-generated fast_scan.c ---" -ForegroundColor Yellow

$cythonFile = "brain/aegis_brain_cython/fast_scan.c"
if (git ls-files --error-unmatch $cythonFile 2>$null) {
    git rm --cached $cythonFile 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] untracked: $cythonFile (463KB Cython generated)" -ForegroundColor Green
    }
} else {
    Write-Host "  [SKIP] $cythonFile not tracked" -ForegroundColor DarkGray
}

Write-Host ""

# Step 3: Update .gitignore to catch all backup patterns
Write-Host "--- Step 3: Update .gitignore ---" -ForegroundColor Yellow

$gitignorePath = Join-Path $repoRoot ".gitignore"
$gitignoreContent = Get-Content $gitignorePath -Raw -Encoding UTF8

# Patterns to ensure are in .gitignore
$requiredPatterns = @(
    "*.bak",
    "*.bak_*",
    "*.phase*_backup",
    "*.phase*backup",
    "*_backup",
    "**/*_backup",
    "brain/aegis_brain_cython/fast_scan.c",
    "brain/aegis_brain_cython/*.c"
)

$added = @()
foreach ($pattern in $requiredPatterns) {
    if ($gitignoreContent -notmatch [regex]::Escape($pattern)) {
        $added += $pattern
    }
}

if ($added.Count -gt 0) {
    Write-Host "  Adding missing patterns to .gitignore:" -ForegroundColor Yellow
    $newPatterns = "`n# G42 cleanup: ensure backup files are ignored`n"
    foreach ($p in $added) {
        $newPatterns += "$p`n"
        Write-Host "    + $p" -ForegroundColor Green
    }
    Add-Content -Path $gitignorePath -Value $newPatterns -Encoding UTF8
    Write-Host "  .gitignore updated with $($added.Count) new patterns" -ForegroundColor Green
} else {
    Write-Host "  .gitignore already has all required patterns." -ForegroundColor DarkGray
}

Write-Host ""

# Step 4: Summary
Write-Host "--- Summary ---" -ForegroundColor Yellow
$remainingBackups = git ls-files 2>$null | Where-Object { $_ -match '\.bak$|_backup$|\.phase.*_backup$' }
Write-Host "  Backup files removed from tracking: $($backupFiles.Count)" -ForegroundColor Green
Write-Host "  Remaining backup files tracked: $($remainingBackups.Count)" -ForegroundColor $(if ($remainingBackups.Count -eq 0) {'Green'} else {'Red'})

if ($remainingBackups.Count -gt 0) {
    Write-Host "  Remaining files:" -ForegroundColor Red
    foreach ($f in $remainingBackups) {
        Write-Host "    - $f" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=== Cleanup complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Review changes:"
Write-Host "       git status" -ForegroundColor Yellow
Write-Host "  2. Commit the cleanup:"
Write-Host "       git add -A" -ForegroundColor Yellow
Write-Host "       git commit -m 'chore: remove 81 backup files + Cython generated code from git tracking'" -ForegroundColor Yellow
Write-Host "  3. Push to GitHub:"
Write-Host "       git push origin main" -ForegroundColor Yellow
Write-Host ""
