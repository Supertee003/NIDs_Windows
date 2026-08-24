# [R44] AEGIS NIDS - BP224 + BP225 + BP226 + BP227
# Deploy: powershell -ExecutionPolicy Bypass -File ./round44_bp224_225_226_227.ps1

$ErrorActionPreference = "Stop"
$projRoot = $PSScriptRoot
$srcFile  = Join-Path $projRoot "nids_analyze_fixed.zig"
$dstFile  = Join-Path $projRoot "core\nids_analyze.zig"
$bakFile  = Join-Path $projRoot "core\nids_analyze.zig.bak_r44"

Write-Host ""
Write-Host "[R44] AEGIS NIDS - BP224 + BP225 + BP226 + BP227" -ForegroundColor Cyan

# --- Pre-flight checks ---
if (-not (Test-Path $srcFile)) {
    Write-Host "[FAIL] Source file not found: $srcFile" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $dstFile)) {
    Write-Host "[FAIL] Target file not found: $dstFile" -ForegroundColor Red
    exit 1
}

$srcLines = (Get-Content $srcFile).Count
Write-Host "[OK] Source file: $srcLines lines" -ForegroundColor Green

# --- BP marker verification ---
$srcContent = Get-Content $srcFile -Raw
$requiredBPs = @("BP224", "BP225", "BP226", "BP227")
$allFound = $true
foreach ($bp in $requiredBPs) {
    if ($srcContent -match $bp) {
        Write-Host "[OK] Found marker: $bp" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] Missing marker: $bp" -ForegroundColor Red
        $allFound = $false
    }
}
if (-not $allFound) {
    Write-Host "[FAIL] BP marker verification failed" -ForegroundColor Red
    exit 1
}

# --- Backup ---
Copy-Item $dstFile $bakFile -Force
Write-Host "[OK] Backed up to: $bakFile" -ForegroundColor Green

# --- Deploy ---
[System.IO.File]::WriteAllText($dstFile, [System.IO.File]::ReadAllText($srcFile), [System.Text.UTF8Encoding]::new($true))
$dstLines = (Get-Content $dstFile).Count
Write-Host "[OK] Written: $dstLines lines to $dstFile" -ForegroundColor Green

if ($dstLines -ne $srcLines) {
    Write-Host "[FAIL] Line count mismatch! src=$srcLines dst=$dstLines" -ForegroundColor Red
    Copy-Item $bakFile $dstFile -Force
    Write-Host "[REVERT] Restored from backup" -ForegroundColor Yellow
    exit 1
}

# --- Build ---
Write-Host ""
Write-Host "[BUILD] Running zig build..." -ForegroundColor Yellow
$buildOutput = & zig build 2>&1
$buildExit = $LASTEXITCODE

if ($buildExit -ne 0) {
    Write-Host "[BUILD FAILED] Exit code: $buildExit" -ForegroundColor Red
    Write-Host ($buildOutput | Out-String)
    Write-Host "[REVERT] Restoring backup..." -ForegroundColor Yellow
    Copy-Item $bakFile $dstFile -Force
    Write-Host "[REVERT] Backup restored from: $bakFile" -ForegroundColor Yellow
    exit 1
}

Write-Host "[BUILD PASSED] Round 44 applied successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Patches applied (4 BPs in one round):" -ForegroundColor Cyan
Write-Host "  BP224: Rules.json pre-flight failures visible in release (too large/empty/not found)" -ForegroundColor White
Write-Host "  BP225: acquireRuleset() null diagnostic log (ruleset unavailable warning)" -ForegroundColor White
Write-Host "  BP226: TCP port override confirmation log via AEGIS_TCP_PORT env" -ForegroundColor White
Write-Host "  BP227: Separate security rejection counter (5 rejection points + status/shutdown)" -ForegroundColor White
Write-Host ""
Write-Host "File grew: 1548 -> $dstLines lines (+$($dstLines - 1548) lines)" -ForegroundColor Green
Write-Host "Backup saved at: $bakFile" -ForegroundColor DarkGray
