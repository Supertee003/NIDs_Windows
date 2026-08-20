# ============================================================
# repo_cleanup.ps1 — Clean up repo artifacts and fix .gitignore
# Run: cd D:\NIDs_Windows
#       powershell -ExecutionPolicy Bypass -File .\repo_cleanup.ps1
# ============================================================

$ErrorActionPreference = 'Continue'
$root = 'D:\NIDs_Windows'

Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '  AEGIS - Repo Cleanup' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan

Push-Location $root

# --- 1. Fix .gitignore ---
Write-Host '' -ForegroundColor Yellow
Write-Host '[1/3] Updating .gitignore ...' -ForegroundColor Yellow

$gitignore = @'
# =====================================================================
# AEGIS NIDS - .gitignore
# =====================================================================

# --- Rust ---
target/
**/*.rs.bk

# --- Zig ---
zig-out/
.zig-cache/

# --- Compiled binaries ---
*.exe
*.dll
*.dll.a
*.pdb
*.obj
*.lib
*.exp
*.so
*.dylib

# --- Driver build ---
*.sys
*.cat
*.cer

# --- C++ build ---
build/
build_cmake/
CMakeFiles/
CMakeCache.txt
cmake_install.cmake
Makefile

# --- Dist (build output) ---
dist/

# --- Python ---
__pycache__/
*.py[cod]
*$py.class
*.pyo
.pytest_cache/
venv/
.venv/

# --- Go ---
*.test
*.out

# --- Generated files ---
threat_graph.html
aegis_threat_map.html

# --- Runtime data ---
logs/anomalous.json
logs/*.log

# --- IDE / Editor ---
.vs/
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store
Thumbs.db

# --- OS ---
desktop.ini

# --- Project scripts (local use) ---
commit_all_fixes.ps1
fix_*.ps1
build_cmake_simple.ps1
build_bridge_cmake.ps1
deploy_*.ps1
verify_*.ps1
apply_shield_fix.ps1
round5_cleanup.ps1
clean_aegis.bat
'@

Set-Content -Path (Join-Path $root '.gitignore') -Value $gitignore -Encoding UTF8
Write-Host '  [OK] .gitignore rewritten (clean, no duplicates)' -ForegroundColor Green

# --- 2. Remove tracked artifacts from git index ---
Write-Host '' -ForegroundColor Yellow
Write-Host '[2/3] Removing tracked artifacts from git ...' -ForegroundColor Yellow

$removed = 0

# Remove dist/ from tracking
if (Test-Path (Join-Path $root 'dist')) {
    & git rm -r --cached 'dist/' 2>&1 | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Gray }
    if ($LASTEXITCODE -eq 0) { $removed++ }
}

# Remove .vs/ from tracking
if (Test-Path (Join-Path $root '.vs')) {
    & git rm -r --cached '.vs/' 2>&1 | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Gray }
    if ($LASTEXITCODE -eq 0) { $removed++ }
}

# Remove threat_graph.html from tracking (if exists)
if (Test-Path (Join-Path $root 'threat_graph.html')) {
    & git rm --cached 'threat_graph.html' 2>&1 | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Gray }
    if ($LASTEXITCODE -eq 0) { $removed++ }
}

# Remove local fix/deploy scripts from tracking
$scriptPatterns = @('commit_all_fixes.ps1','fix_dll_and_deploy.ps1','build_cmake_simple.ps1','build_bridge_cmake.ps1','deploy_runtime.ps1','deploy_shield.ps1','verify_cmake.ps1','verify_all.ps1','apply_shield_fix.ps1','round5_cleanup.ps1')
foreach ($s in $scriptPatterns) {
    $f = Join-Path $root $s
    if (Test-Path $f) {
        & git rm --cached $s 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host ('  Untracked: ' + $s) -ForegroundColor Gray
            $removed++
        }
    }
}

Write-Host ('  [OK] Removed ' + $removed + ' items from git tracking') -ForegroundColor Green

# --- 3. Stage and show status ---
Write-Host '' -ForegroundColor Yellow
Write-Host '[3/3] Staging and committing ...' -ForegroundColor Yellow

& git add -A

Write-Host '' -ForegroundColor Cyan
Write-Host 'Git status after cleanup:' -ForegroundColor Cyan
& git status --short

# Commit
$msgFile = Join-Path $env:TEMP 'aegis_cleanup_msg.txt'
$msgText = @'
chore: repo cleanup - fix .gitignore, remove build artifacts

- Rewrite .gitignore: remove duplicates, add dist/ .vs/ *.dll.a
- Remove dist/ from tracking (build output)
- Remove .vs/ from tracking (IDE settings)
- Remove local fix/deploy scripts from tracking
- Add script patterns to .gitignore
'@
Set-Content -Path $msgFile -Value $msgText -NoNewline -Encoding UTF8

& git commit -F $msgFile
$commitRC = $LASTEXITCODE
Remove-Item $msgFile -Force -ErrorAction SilentlyContinue

if ($commitRC -eq 0) {
    Write-Host '' -ForegroundColor Green
    Write-Host '  [OK] Committed cleanup' -ForegroundColor Green

    Write-Host '  Pushing ...' -ForegroundColor Yellow
    & git push origin main 2>&1 | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Gray }

    if ($LASTEXITCODE -eq 0) {
        Write-Host '  [OK] Pushed!' -ForegroundColor Green
    }
} else {
    Write-Host '  [INFO] Nothing to commit or no changes' -ForegroundColor DarkYellow
}

Pop-Location

Write-Host '' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '  Done.' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
