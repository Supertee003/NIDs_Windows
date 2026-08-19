# ============================================================================
# AEGIS NIDS - Fix Console Imports (shared/ path + __init__.py)
# Fixes ModuleNotFoundError for aegis_bridge_ctypes
# Usage: powershell -ExecutionPolicy Bypass -File .\scripts\fix_console_imports.ps1
# ============================================================================

 $ErrorActionPreference = "Continue"
 $Root = $PSScriptRoot
if (-not $Root) { $Root = Split-Path -Parent $MyInvocation.MyCommand.Path }
while ($Root -and -not (Test-Path (Join-Path $Root "brain")) -and -not (Test-Path (Join-Path $Root "core"))) {
    $Root = Split-Path -Parent $Root
}
if (-not $Root) { $Root = "D:\NIDs_Windows" }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Fix Console Imports" -ForegroundColor Cyan
Write-Host " Root: $Root" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

 $fixCount = 0

# ---- Fix 1: Create __init__.py in Python packages ----
Write-Host "[1] Creating __init__.py in Python packages..." -ForegroundColor Yellow

 $initDirs = @("shared", "brain", "config", "dist", "bridge")
foreach ($dir in $initDirs) {
    $dirPath = Join-Path $Root $dir
    $initFile = Join-Path $dirPath "__init__.py"
    
    if (Test-Path $dirPath) {
        if (-not (Test-Path $initFile)) {
            Set-Content -Path $initFile -Value "# AEGIS NIDS package marker`n" -Encoding UTF8
            Write-Host "  [OK] Created $dir\__init__.py" -ForegroundColor Green
            $fixCount++
        } else {
            Write-Host "  [--] $dir\__init__.py already exists" -ForegroundColor Gray
        }
    } else {
        Write-Host "  [SKIP] $dir/ directory not found" -ForegroundColor Yellow
    }
}

# ---- Fix 2: Fix aegis_console.py path injection ----
Write-Host ""
Write-Host "[2] Fixing aegis_console.py shared/ path..." -ForegroundColor Yellow

 $consoleFile = Join-Path $Root "scripts\aegis_console.py"
if (Test-Path $consoleFile) {
    $content = Get-Content $consoleFile -Raw -ErrorAction SilentlyContinue
    
    $pathInjection = @"
# === AEGIS Path Setup (robust - works from any directory) ===
import sys as _sys
import os as _os
_aegis_script_dir = _os.path.dirname(_os.path.abspath(__file__))
_aegis_root = _os.path.dirname(_aegis_script_dir)
if not _os.path.exists(_os.path.join(_aegis_root, 'brain')):
    _aegis_root = _aegis_script_dir
for _pkg in ['shared', 'brain', 'config', 'dist', 'bridge']:
    _pkg_dir = _os.path.join(_aegis_root, _pkg)
    if _os.path.isdir(_pkg_dir) and _pkg_dir not in _sys.path:
        _sys.path.insert(0, _pkg_dir)
"@

    if ($content -match "AEGIS Path Setup.*robust") {
        Write-Host "  Already patched with robust path injection" -ForegroundColor Green
    } else {
        $backupFile = $consoleFile + ".bak_import_fix"
        Copy-Item $consoleFile $backupFile -Force
        Write-Host "  Backup: $backupFile" -ForegroundColor Yellow
        
        $lines = Get-Content $consoleFile
        $newLines = [System.Collections.ArrayList]::new()
        $patched = $false
        
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if (-not $patched -and $lines[$i] -match "sys\.path\.insert.*shared") {
                foreach ($pl in $pathInjection.Split("`n")) {
                    [void]$newLines.Add($pl.TrimEnd())
                }
                $patched = $true
                Write-Host "  Replaced line $($i+1) with robust path injection" -ForegroundColor Green
                $fixCount++
            } else {
                [void]$newLines.Add($lines[$i])
            }
        }
        
        if ($patched) {
            $output = $newLines -join "`r`n"
            [System.IO.File]::WriteAllText($consoleFile, $output, (New-Object System.Text.UTF8Encoding($false)))
            Write-Host "  Written to aegis_console.py" -ForegroundColor Green
        } else {
            Write-Host "  Could not find sys.path.insert line - adding after imports" -ForegroundColor Yellow
            
            $newLines2 = [System.Collections.ArrayList]::new()
            $patched2 = $false
            $lines2 = Get-Content $consoleFile
            
            for ($i = 0; $i -lt $lines2.Count; $i++) {
                [void]$newLines2.Add($lines2[$i])
                if (-not $patched2 -and $lines2[$i] -match "from datetime import datetime") {
                    [void]$newLines2.Add("")
                    foreach ($pl in $pathInjection.Split("`n")) {
                        [void]$newLines2.Add($pl.TrimEnd())
                    }
                    $patched2 = $true
                    Write-Host "  Added path injection after line $($i+1)" -ForegroundColor Green
                    $fixCount++
                }
            }
            
            if ($patched2) {
                $output2 = $newLines2 -join "`r`n"
                [System.IO.File]::WriteAllText($consoleFile, $output2, (New-Object System.Text.UTF8Encoding($false)))
            }
        }
    }
} else {
    Write-Host "  scripts\aegis_console.py not found" -ForegroundColor Red
}

# ---- Fix 3: Verify Brain path injection ----
Write-Host ""
Write-Host "[3] Checking brain\windows_brain.py path injection..." -ForegroundColor Yellow

 $brainFile = Join-Path $Root "brain\windows_brain.py"
if (Test-Path $brainFile) {
    $brainContent = Get-Content $brainFile -Raw -ErrorAction SilentlyContinue
    if ($brainContent -match "AEGIS Path Setup") {
        Write-Host "  Brain already has path injection" -ForegroundColor Green
    } else {
        Write-Host "  Brain needs path injection" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " DONE - Applied $fixCount fix(es)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Test: python scripts\aegis_console.py" -ForegroundColor Yellow
Write-Host ""