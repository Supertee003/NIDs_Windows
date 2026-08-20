# ============================================================
# commit_all_fixes.ps1 — Commit and push all Phase Next fixes
# Run: cd D:\NIDs_Windows
#       powershell -ExecutionPolicy Bypass -File .\commit_all_fixes.ps1
# ============================================================

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  AEGIS - Commit All Phase Next Fixes to GitHub" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Push-Location 'D:\NIDs_Windows'

# --- Show git status ---
Write-Host '' -ForegroundColor Yellow
Write-Host '[1/4] Git status:' -ForegroundColor Yellow
& git status --short

# --- Show changed files summary ---
Write-Host '' -ForegroundColor Yellow
Write-Host '[2/4] Changed files:' -ForegroundColor Yellow
$changed = & git diff --stat
$changed | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Gray }

# --- Stage all changes ---
Write-Host '' -ForegroundColor Yellow
Write-Host '[3/4] Staging all changes ...' -ForegroundColor Yellow
& git add -A
$stageRC = $LASTEXITCODE
if ($stageRC -eq 0) {
    Write-Host '  [OK] All files staged' -ForegroundColor Green
} else {
    Write-Host '  [WARN] git add had issues' -ForegroundColor DarkYellow
}

# --- Commit and push ---
Write-Host '' -ForegroundColor Yellow
Write-Host '[4/4] Committing and pushing ...' -ForegroundColor Yellow

# Write commit message to temp file
$msgFile = Join-Path $env:TEMP 'aegis_commit_msg.txt'
$msgText = @'
fix: Phase Next - all 29 critical bugs resolved

Round 2 (H1+H2+H3): nids_analyze.zig
- Add missing semicolons after catch/labeled block expressions
- Fix AegisIpcEvent to packed struct for FFI compatibility
- Fix callconv(.c) to callconv(.C) for Zig 0.13.0
- Fix DynLib lookup to use mutable pointer capture
- Clean 27 broken ANSI escape codes

Round 3 (M3+M4): shield/src/lib.rs
- Fix FFI scoring: severity scale (25/50/75/100) x confidence
- Add DEFAULT_THRESHOLD, severity_to_numeric, aegis_score_event_str

Bridge (CMake):
- Add PREFIX to CMakeLists.txt for MinGW compatibility
- DLL now outputs as aegis_ipc.dll (not libaegis_ipc.dll)

All 3 builds pass: zig build, cargo build, cmake build
'@
Set-Content -Path $msgFile -Value $msgText -NoNewline -Encoding UTF8

& git commit -F $msgFile
$commitRC = $LASTEXITCODE
Remove-Item $msgFile -Force -ErrorAction SilentlyContinue

if ($commitRC -eq 0) {
    Write-Host '  [OK] Committed successfully' -ForegroundColor Green
    
    Write-Host '' -ForegroundColor Yellow
    Write-Host '  Pushing to origin/main ...' -ForegroundColor Yellow
    & git push origin main 2>&1
    $pushRC = $LASTEXITCODE
    
    if ($pushRC -eq 0) {
        Write-Host '  [OK] Pushed to GitHub!' -ForegroundColor Green
    } else {
        Write-Host '  [WARN] Push failed - you may need to auth or resolve conflicts' -ForegroundColor DarkYellow
        Write-Host '  Try: git push origin main' -ForegroundColor Gray
    }
} else {
    Write-Host '  [WARN] Commit had issues (possibly nothing to commit or auth needed)' -ForegroundColor DarkYellow
}

Pop-Location

Write-Host '' -ForegroundColor Cyan
Write-Host 'Done.' -ForegroundColor Cyan
