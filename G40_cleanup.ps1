# G40: Repository Cleanup - Remove all junk files before GitHub push
# Scans for and removes ALL tracked junk files, then cleans working directory

$DeployRoot = $PSScriptRoot
if (-not $DeployRoot) { $DeployRoot = (Get-Location).Path }

Write-Host "[G40] Repository Cleanup" -ForegroundColor Cyan
Write-Host ""

# === STEP 1: Remove tracked junk files from git index ===
Write-Host "[Step 1] Removing tracked junk files..." -ForegroundColor Yellow

$junkPatterns = @(
    # Backup files
    "build.zig.*_backup",
    "build.zig.bak",
    "build.zig.backup_g*",
    "generate_deploy_script.py.*_backup",
    "*.phase*_backup",
    # Build logs
    "build_stdout.txt",
    "build_stderr.txt",
    "build_r15_stdout.txt",
    "build_r15_stderr.txt",
    "build_r15c_stdout.txt",
    "build_r15c_stderr.txt",
    "build_r16_stdout.txt",
    "build_r16_stderr.txt",
    "verify_build.stdout",
    "verify_build.stderr",
    # Stray root files
    "threat_graph.html",
    "IDEA.md",
    "G38_all_files.ps1"
)

$removedCount = 0
foreach ($pattern in $junkPatterns) {
    $files = Get-ChildItem -Path $DeployRoot -Filter $pattern -File -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        # Remove from git index
        git -C $DeployRoot rm --cached $f.Name 2>$null
        # Remove from disk
        Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
        Write-Host "  [REMOVED] $($f.Name)" -ForegroundColor Green
        $removedCount++
    }
}

# Remove .zig-cache from git index
$zigCache = Join-Path $DeployRoot ".zig-cache"
if (Test-Path $zigCache) {
    git -C $DeployRoot rm --cached -r .zig-cache 2>$null
    Write-Host "  [REMOVED] .zig-cache/ from git index" -ForegroundColor Green
    $removedCount++
}

# Remove duplicate nids_main.zig at root (if exists and different from core/)
$rootNidsMain = Join-Path $DeployRoot "nids_main.zig"
$coreNidsMain = Join-Path $DeployRoot "core\nids_main.zig"
if (Test-Path $rootNidsMain -and (Test-Path $coreNidsMain)) {
    git -C $DeployRoot rm --cached nids_main.zig 2>$null
    Remove-Item $rootNidsMain -Force -ErrorAction SilentlyContinue
    Write-Host "  [REMOVED] duplicate nids_main.zig at root" -ForegroundColor Green
    $removedCount++
}

Write-Host "  Total removed: $removedCount items" -ForegroundColor Cyan

# === STEP 2: Remove backup directories from disk ===
Write-Host ""
Write-Host "[Step 2] Removing backup directories..." -ForegroundColor Yellow

$backupDirs = Get-ChildItem -Path $DeployRoot -Directory -Filter "backup_*" -ErrorAction SilentlyContinue
$dirCount = 0
foreach ($d in $backupDirs) {
    Remove-Item $d.FullName -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  [REMOVED] $($d.Name)/" -ForegroundColor Green
    $dirCount++
}
if ($dirCount -eq 0) {
    Write-Host "  No backup directories found" -ForegroundColor Gray
} else {
    Write-Host "  Total removed: $dirCount directories" -ForegroundColor Cyan
}

# === STEP 3: Remove .zig-cache from disk ===
Write-Host ""
Write-Host "[Step 3] Removing .zig-cache..." -ForegroundColor Yellow
if (Test-Path $zigCache) {
    Remove-Item $zigCache -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  [REMOVED] .zig-cache/" -ForegroundColor Green
} else {
    Write-Host "  .zig-cache not found (already clean)" -ForegroundColor Gray
}

# === STEP 4: Remove .ps1 deploy scripts from root (optional - keep if needed) ===
Write-Host ""
Write-Host "[Step 4] Checking for stray .ps1 files..." -ForegroundColor Yellow
$strayPs1 = Get-ChildItem -Path $DeployRoot -Filter "G*.ps1" -File -ErrorAction SilentlyContinue
if ($strayPs1) {
    foreach ($f in $strayPs1) {
        Write-Host "  Found: $($f.Name) (keeping - move to scripts/ if needed)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  No stray .ps1 files" -ForegroundColor Gray
}

# === STEP 5: Verify .gitignore is correct ===
Write-Host ""
Write-Host "[Step 5] Verifying .gitignore..." -ForegroundColor Yellow
$gitignorePath = Join-Path $DeployRoot ".gitignore"
if (Test-Path $gitignorePath) {
    $content = Get-Content $gitignorePath -Raw
    
    $required = @(
        @(".zig-cache/", "Zig cache"),
        @("*.bak", "Backup files"),
        @("*_backup", "Backup suffix"),
        @("build_*.txt", "Build logs"),
        @("verify_build.*", "Verify logs"),
        @("backup_*/", "Backup directories"),
        @("logs/", "Log directory"),
        @("*.ndjson", "NDJSON files")
    )
    
    foreach ($r in $required) {
        if ($content.Contains($r[0])) {
            Write-Host "  [OK] $($r[0]) - $($r[1])" -ForegroundColor Green
        } else {
            $content = $content + "`n" + $r[0] + "`n"
            Write-Host "  [ADDED] $($r[0]) - $($r[1])" -ForegroundColor Yellow
        }
    }
    
    Set-Content -Path $gitignorePath -Value $content -NoNewline -Encoding UTF8
    Write-Host "  [DONE] .gitignore verified" -ForegroundColor Green
}

# === STEP 6: Remove empty directories ===
Write-Host ""
Write-Host "[Step 6] Removing empty directories..." -ForegroundColor Yellow
$emptyDirs = Get-ChildItem -Path $DeployRoot -Directory -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { (Get-ChildItem $_.FullName -Force -ErrorAction SilentlyContinue).Count -eq 0 }
foreach ($d in $emptyDirs) {
    Remove-Item $d.FullName -Force -ErrorAction SilentlyContinue
    Write-Host "  [REMOVED] empty: $($d.Name)/" -ForegroundColor Green
}

# === STEP 7: Summary ===
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "G40 CLEANUP COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Files removed from git index: $removedCount"
Write-Host "Backup directories removed: $dirCount"
Write-Host ""
Write-Host "Ready to commit:"
Write-Host "  git add -A"
Write-Host "  git commit -m `"chore: remove tracked junk files, fix .gitignore`""
Write-Host "  git push"
Write-Host ""
Write-Host "Verify CI passes after push."
