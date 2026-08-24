# =================================================================
# AEGIS NIDS - .gitignore Update Script
# =================================================================
# Fixes: HYG-001, HYG-002, HYG-003, HYG-004, HYG-005
# Removes 20+ .bak files from tracking, cleans root directory
# =================================================================

$ErrorActionPreference = "Stop"

# Verify we're in repo root
if (-not (Test-Path ".git")) {
    Write-Host "[ERROR] Not in repo root directory." -ForegroundColor Red
    Write-Host "Please run this script from the root of NIds_Windows." -ForegroundColor Red
    exit 1
}

Write-Host "[FIX] Updating .gitignore..." -ForegroundColor Cyan

# Read current .gitignore
$gitignorePath = Join-Path $PWD ".gitignore"
$gitignore = @"
# === Build Artifacts ===
zig-out/
build/
target/
*.obj
*.o
*.exe
*.dll
*.pdb
*.lib
*.exp

# === Backup Files (REMOVE FROM GIT) ===
*.bak
*.bak_*
*.bak_r*

# === Empty/Temp Build Logs ===
build_*.txt
build_*.stderr.txt
build_*.stdout.txt
verify_build.*

# === PID Files ===
logs/pids/
*.pid

# === Logs ===
*.log
logs/*.log

# === Config Backups ===
config/Back_*.json

# === Standalone fixed file (should be in core/) ===
nids_analyze_fixed.zig

# === OS Files ===
Thumbs.db
.DS_Store
desktop.ini

# === Python ===
__pycache__/
*.pyc
*.pyo
.venv/
venv/

# === Rust ===
target/
Cargo.lock

# === CMake ===
CMakeCache.txt
CMakeFiles/
cmake_install.cmake

# === IDE ===
.vs/
.idea/
*.swp
*.swo
*~

# === Round deployment scripts (temporary) ===
round*.ps1

"@

[System.IO.File]::WriteAllText($gitignorePath, $gitignore, [System.Text.Encoding]::UTF8)
Write-Host "  [OK] .gitignore updated" -ForegroundColor Green

# Remove tracked files that should not be in git
Write-Host ""
Write-Host "[FIX] Removing tracked files that should be ignored..." -ForegroundColor Cyan

$removedCount = 0

# Remove .bak files from core/
$coreBaks = Get-ChildItem -Path "core\*.bak*" -File -ErrorAction SilentlyContinue
foreach ($f in $coreBaks) {
    git rm --cached $f.FullName 2>$null
    $removedCount++
    Write-Host "  [DEL] $($f.Name)" -ForegroundColor DarkGray
}

# Remove standalone nids_analyze_fixed.zig from root
if (Test-Path "nids_analyze_fixed.zig") {
    git rm --cached "nids_analyze_fixed.zig" 2>$null
    $removedCount++
    Write-Host "  [DEL] nids_analyze_fixed.zig" -ForegroundColor DarkGray
}

# Remove empty build logs from root
$emptyFiles = Get-ChildItem -Path ".\build_*.txt", ".\verify_build.*" -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -eq 0 }
foreach ($f in $emptyFiles) {
    git rm --cached $f.FullName 2>$null
    $removedCount++
    Write-Host "  [DEL] $($f.Name) (empty)" -ForegroundColor DarkGray
}

# Remove deployment scripts from root
$roundScripts = Get-ChildItem -Path ".\round*.ps1" -File -ErrorAction SilentlyContinue
foreach ($f in $roundScripts) {
    git rm --cached $f.FullName 2>$null
    $removedCount++
    Write-Host "  [DEL] $($f.Name) (deployment artifact)" -ForegroundColor DarkGray
}

# Remove config backups
if (Test-Path "config\Back_Rules.json") {
    git rm --cached "config\Back_Rules.json" 2>$null
    $removedCount++
    Write-Host "  [DEL] config\Back_Rules.json" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "[DONE] Removed $removedCount files from git tracking." -ForegroundColor Green
Write-Host "[NOTE] Files still exist on disk. Commit .gitignore first, then commit the removal." -ForegroundColor Yellow
Write-Host ""
Write-Host "Suggested git commands:" -ForegroundColor Cyan
Write-Host "  git add .gitignore" -ForegroundColor White
Write-Host "  git commit -m 'chore: update .gitignore and remove tracked artifacts'" -ForegroundColor White
Write-Host "  git push" -ForegroundColor White
