# =====================================================================
#  list_all_files.ps1 — AEGIS NIDS Full Project File Listing
# =====================================================================
#  List all files for review before cleanup
#
#  Usage:
#    powershell -ExecutionPolicy Bypass -File scripts\list_all_files.ps1
#    powershell -ExecutionPolicy Bypass -File scripts\list_all_files.ps1 -NoGit
#    powershell -ExecutionPolicy Bypass -File scripts\list_all_files.ps1 -OutputFile listing.txt
# =====================================================================

param(
    [switch]$NoGit     = $false,
    [string]$OutputFile = ""
)

# -- Auto-detect Project Root --
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = $null

if (Test-Path "$ScriptDir\..\core")       { $ProjectRoot = Resolve-Path "$ScriptDir\.." }
elseif (Test-Path "$ScriptDir\core")      { $ProjectRoot = Resolve-Path $ScriptDir }
elseif (Test-Path "$ScriptDir\..\..\core") { $ProjectRoot = Resolve-Path "$ScriptDir\..\.." }

if (-not $ProjectRoot) {
    Write-Host "[ERROR] Cannot find AEGIS NIDS project root!" -ForegroundColor Red
    exit 1
}

Set-Location $ProjectRoot

# -- Output buffer --
$Output = [System.Text.StringBuilder]::new()

function Write-Both {
    param([string]$Text = "")
    Write-Host $Text
    [void]$Output.AppendLine($Text)
}

function FmtSize {
    param([long]$Bytes)
    if ($Bytes -ge 1MB) { return "{0:N1} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N1} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

# -- Header --
Write-Both ""
Write-Both "  +============================================================+"
Write-Both "  |        AEGIS NIDS -- Full Project File Listing              |"
Write-Both "  +============================================================+"
Write-Both ""
Write-Both "  Project root: $ProjectRoot"
$now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Both "  Date: $now"
Write-Both ""

# -- Collect all files --
Write-Both "  Scanning all files..."
$AllFiles = Get-ChildItem -Path $ProjectRoot -Recurse -File -ErrorAction SilentlyContinue

if ($NoGit) {
    $AllFiles = $AllFiles | Where-Object { $_.FullName -notlike "*\.git\*" }
}

$AllDirs = Get-ChildItem -Path $ProjectRoot -Recurse -Directory -ErrorAction SilentlyContinue
if ($NoGit) {
    $AllDirs = $AllDirs | Where-Object { $_.FullName -notlike "*\.git\*" }
}

$TotalFiles = $AllFiles.Count
$TotalDirs  = $AllDirs.Count
$TotalSize  = ($AllFiles | Measure-Object -Property Length -Sum).Sum

$totalSizeStr = FmtSize $TotalSize
Write-Both "  Found: $TotalFiles files, $TotalDirs directories, $totalSizeStr total"
Write-Both ""

# =====================================================================
#  Section 1: Directory Tree (compact)
# =====================================================================
Write-Both "  ================================================================"
Write-Both "  SECTION 1: DIRECTORY TREE"
Write-Both "  ================================================================"
Write-Both ""

$TopDirs = Get-ChildItem -Path $ProjectRoot -Directory -ErrorAction SilentlyContinue
if ($NoGit) {
    $TopDirs = $TopDirs | Where-Object { $_.Name -ne ".git" }
}
$TopDirs = $TopDirs | Sort-Object Name

Write-Both "  NIDs_Windows/"
foreach ($d in $TopDirs) {
    $subFiles = Get-ChildItem -Path $d.FullName -Recurse -File -ErrorAction SilentlyContinue
    $subCount = $subFiles.Count
    $subSizeVal = ($subFiles | Measure-Object -Property Length -Sum).Sum
    $subSize = FmtSize $subSizeVal
    $subDirsCount = (Get-ChildItem -Path $d.FullName -Recurse -Directory -ErrorAction SilentlyContinue).Count
    $dirName = $d.Name
    Write-Both "  +-- $dirName/  ($subCount files, $subDirsCount dirs, $subSize)"
}

$RootFiles = Get-ChildItem -Path $ProjectRoot -File -ErrorAction SilentlyContinue | Sort-Object Name
foreach ($f in $RootFiles) {
    $fSize = FmtSize $f.Length
    $fName = $f.Name
    Write-Both "  +-- $fName  ($fSize)"
}
Write-Both ""

# =====================================================================
#  Section 2: Full File List
# =====================================================================
Write-Both "  ================================================================"
Write-Both "  SECTION 2: FULL FILE LIST (sorted by path)"
Write-Both "  ================================================================"
Write-Both ""
Write-Both "  SIZE            EXT        LAST_MODIFIED        PATH"
Write-Both "  ------------------------------------------------------------"

$SortedFiles = $AllFiles | Sort-Object { $_.FullName.Substring($ProjectRoot.Path.Length + 1) }

foreach ($f in $SortedFiles) {
    $relPath = $f.FullName.Substring($ProjectRoot.Path.Length + 1)
    $ext = if ($f.Extension) { $f.Extension.TrimStart(".") } else { "-" }
    $modDate = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
    $sizeStr = FmtSize $f.Length
    $line = "  {0,-14} {1,-10} {2,-20} {3}" -f $sizeStr, $ext, $modDate, $relPath
    Write-Both $line
}
Write-Both ""

# =====================================================================
#  Section 3: Summary by Extension
# =====================================================================
Write-Both "  ================================================================"
Write-Both "  SECTION 3: SUMMARY BY FILE EXTENSION"
Write-Both "  ================================================================"
Write-Both ""

$ExtGroups = $AllFiles | Group-Object { if ($_.Extension) { $_.Extension.ToLower() } else { "(no ext)" } }
$ExtGroups = $ExtGroups | Sort-Object Count -Descending

Write-Both "  EXT            COUNT     TOTAL_SIZE     CATEGORY"
Write-Both "  --------------------------------------------------------"

function Get-FileCategory {
    param([string]$Ext)
    switch ($Ext) {
        ".go"    { return "Go source" }
        ".rs"    { return "Rust source" }
        ".zig"   { return "Zig source" }
        ".py"    { return "Python source" }
        ".pyc"   { return "Python cache" }
        ".cpp"   { return "C++ source" }
        ".hpp"   { return "C++ header" }
        ".c"     { return "C source" }
        ".h"     { return "C header" }
        ".java"  { return "Java source" }
        ".js"    { return "JavaScript" }
        ".css"   { return "CSS" }
        ".bat"   { return "Batch script" }
        ".ps1"   { return "PowerShell" }
        ".sh"    { return "Shell script" }
        ".json"  { return "JSON config" }
        ".xml"   { return "XML config" }
        ".toml"  { return "TOML config" }
        ".md"    { return "Markdown doc" }
        ".txt"   { return "Text" }
        ".exe"   { return "Executable" }
        ".dll"   { return "DLL" }
        ".so"    { return "Shared lib" }
        ".o"     { return "Object file" }
        ".obj"   { return "Object file" }
        ".lib"   { return "Static lib" }
        ".a"     { return "Static lib" }
        ".pdb"   { return "Debug symbols" }
        ".ilk"   { return "Incremental link" }
        ".exp"   { return "Export file" }
        ".bak"   { return "BACKUP" }
        ".old"   { return "BACKUP" }
        ".orig"  { return "BACKUP" }
        ".tmp"   { return "TEMP" }
        ".log"   { return "Log file" }
        ".pid"   { return "PID file" }
        ".inf"   { return "Driver inf" }
        ".pyx"   { return "Cython source" }
        ".pxd"   { return "Cython decl" }
        ".lock"  { return "Lock file" }
        default  { return "Other" }
    }
}

foreach ($g in $ExtGroups) {
    $groupSize = ($g.Group | Measure-Object -Property Length -Sum).Sum
    $groupSizeStr = FmtSize $groupSize
    $category = Get-FileCategory $g.Name
    $extName = $g.Name
    $extCount = $g.Count
    $line = "  {0,-14} {1,-9} {2,-14} {3}" -f $extName, $extCount, $groupSizeStr, $category
    Write-Both $line
}
Write-Both ""

# =====================================================================
#  Section 4: Potentially Unnecessary Files
# =====================================================================
Write-Both "  ================================================================"
Write-Both "  SECTION 4: POTENTIALLY UNNECESSARY FILES"
Write-Both "  ================================================================"
Write-Both ""

# Backup/Temp/Cache files
$JunkExts = @(".bak", ".backup", ".old", ".orig", ".tmp", ".temp", ".swp", ".swo",
              ".pyc", ".pyo", ".o", ".obj", ".pdb", ".ilk", ".exp", ".lib", ".d")
$JunkFiles = $AllFiles | Where-Object { $JunkExts -contains $_.Extension.ToLower() }

Write-Both "  --- Backup/Temp/Cache files ---"
if ($JunkFiles.Count -gt 0) {
    $JunkSorted = $JunkFiles | Sort-Object { $_.FullName.Substring($ProjectRoot.Path.Length + 1) }
    foreach ($f in $JunkSorted) {
        $relPath = $f.FullName.Substring($ProjectRoot.Path.Length + 1)
        $fSize = FmtSize $f.Length
        Write-Both "    [JUNK]    $fSize  $relPath"
    }
} else {
    Write-Both "    (none found)"
}
Write-Both ""

# One-shot fix/debug scripts
Write-Both "  --- Fix/Debug one-shot scripts ---"
$OneShotFiles = $AllFiles | Where-Object {
    $rel = $_.FullName.Substring($ProjectRoot.Path.Length + 1)
    ($rel -like "scripts\fix_*") -or ($rel -like "scripts\diag_console_*") -or
    ($rel -like "scripts\test_console_*") -or ($rel -like "scripts\*idempotent_*") -or
    ($rel -like "scripts\*win_test*") -or ($rel -like "scripts\verify_*")
}
if ($OneShotFiles.Count -gt 0) {
    $OneShotSorted = $OneShotFiles | Sort-Object { $_.FullName.Substring($ProjectRoot.Path.Length + 1) }
    foreach ($f in $OneShotSorted) {
        $relPath = $f.FullName.Substring($ProjectRoot.Path.Length + 1)
        $fSize = FmtSize $f.Length
        Write-Both "    [ONESHOT] $fSize  $relPath"
    }
} else {
    Write-Both "    (none found)"
}
Write-Both ""

# Large fix scripts at root
Write-Both "  --- Large fix scripts at project root ---"
$RootFixScripts = Get-ChildItem -Path $ProjectRoot -Filter "fix_aegis_*.ps1" -File -ErrorAction SilentlyContinue
if ($RootFixScripts.Count -gt 0) {
    foreach ($f in $RootFixScripts) {
        $fSize = FmtSize $f.Length
        Write-Both "    [FIX]     $fSize  $($f.Name)"
    }
} else {
    Write-Both "    (none found)"
}
Write-Both ""

# Cache directories
Write-Both "  --- Large cache directories ---"
$CacheDirList = @(
    @{ Name = ".zig-cache"; Path = Join-Path $ProjectRoot ".zig-cache" },
    @{ Name = "target";     Path = Join-Path $ProjectRoot "target" },
    @{ Name = "build";      Path = Join-Path $ProjectRoot "build" },
    @{ Name = "zig-out";    Path = Join-Path $ProjectRoot "zig-out" }
)
$foundCache = $false
foreach ($cache in $CacheDirList) {
    if (Test-Path $cache.Path) {
        $cacheFiles = Get-ChildItem -Path $cache.Path -Recurse -File -ErrorAction SilentlyContinue
        $cacheSize = ($cacheFiles | Measure-Object -Property Length -Sum).Sum
        $cacheSizeStr = FmtSize $cacheSize
        $cacheCount = $cacheFiles.Count
        $cacheName = $cache.Name
        Write-Both "    [CACHE]   $cacheSizeStr  $cacheName/ ($cacheCount files)"
        $foundCache = $true
    }
}

# __pycache__ dirs
$PycacheDirs = Get-ChildItem -Path $ProjectRoot -Directory -Filter "__pycache__" -Recurse -ErrorAction SilentlyContinue
foreach ($d in $PycacheDirs) {
    $pycFiles = Get-ChildItem -Path $d.FullName -Recurse -File -ErrorAction SilentlyContinue
    $pycSize = ($pycFiles | Measure-Object -Property Length -Sum).Sum
    $pycSizeStr = FmtSize $pycSize
    $pycCount = $pycFiles.Count
    $relPath = $d.FullName.Substring($ProjectRoot.Path.Length + 1)
    Write-Both "    [PYCACHE] $pycSizeStr  $relPath\ ($pycCount files)"
    $foundCache = $true
}

if (-not $foundCache) {
    Write-Both "    (none found)"
}
Write-Both ""

# Stale PID files
Write-Both "  --- PID files ---"
$PidDir = Join-Path $ProjectRoot "logs\pids"
if (Test-Path $PidDir) {
    $PidFiles = Get-ChildItem -Path $PidDir -Filter "*.pid" -File -ErrorAction SilentlyContinue
    if ($PidFiles.Count -gt 0) {
        foreach ($f in $PidFiles) {
            $pidContent = Get-Content $f.FullName -ErrorAction SilentlyContinue
            $isStale = $true
            if ($pidContent -match "^\d+$") {
                $proc = Get-Process -Id ([int]$pidContent) -ErrorAction SilentlyContinue
                if ($proc) { $isStale = $false }
            }
            $status = if ($isStale) { "STALE" } else { "ACTIVE" }
            Write-Both "    [$status]  PID=$pidContent  $($f.Name)"
        }
    } else {
        Write-Both "    (no PID files)"
    }
} else {
    Write-Both "    (no PID directory)"
}
Write-Both ""

# =====================================================================
#  Section 5: Disk Usage by Top-Level Directory
# =====================================================================
Write-Both "  ================================================================"
Write-Both "  SECTION 5: DISK USAGE BY TOP-LEVEL DIRECTORY"
Write-Both "  ================================================================"
Write-Both ""

Write-Both "  DIRECTORY           FILES     SIZE"
Write-Both "  ---------------------------------------------"

$DirUsage = @()
$TopLevelDirs = Get-ChildItem -Path $ProjectRoot -Directory -ErrorAction SilentlyContinue
if ($NoGit) {
    $TopLevelDirs = $TopLevelDirs | Where-Object { $_.Name -ne ".git" }
}

foreach ($d in $TopLevelDirs) {
    $files = Get-ChildItem -Path $d.FullName -Recurse -File -ErrorAction SilentlyContinue
    $size = if ($files.Count -gt 0) { ($files | Measure-Object -Property Length -Sum).Sum } else { 0 }
    $DirUsage += [PSCustomObject]@{
        Name  = $d.Name
        Files = $files.Count
        Size  = $size
    }
}

$DirUsage = $DirUsage | Sort-Object Size -Descending

foreach ($d in $DirUsage) {
    $dSize = FmtSize $d.Size
    $line = "  {0,-20} {1,-9} {2}" -f $d.Name, $d.Files, $dSize
    Write-Both $line
}
Write-Both ""

# -- Grand Total --
$totalStr = FmtSize $TotalSize
Write-Both "  ================================================================"
Write-Both "  GRAND TOTAL: $TotalFiles files | $TotalDirs dirs | $totalStr"
Write-Both "  ================================================================"
Write-Both ""

# -- Write to file if requested --
if ($OutputFile -ne "") {
    $outPath = if ([System.IO.Path]::IsPathRooted($OutputFile)) { $OutputFile } else { Join-Path $ProjectRoot $OutputFile }
    $Output.ToString() | Out-File -FilePath $outPath -Encoding UTF8
    Write-Host "  Output written to: $outPath" -ForegroundColor Green
    Write-Host ""
}
