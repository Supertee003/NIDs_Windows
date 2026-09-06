# ============================================================
# AEGIS NIDS - Phase 33: SIEM Forwarder CLI
# ============================================================
# Forwards events from logs/anomalous.json to SIEM-compatible format.
# Supports: NDJSON, CEF, Syslog formats.
# Default output: logs/siem_forward.json
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\generate_siem_report.ps1
#   powershell -ExecutionPolicy Bypass -File .\generate_siem_report.ps1 -Format cef
#   powershell -ExecutionPolicy Bypass -File .\generate_siem_report.ps1 -Format syslog -Output logs/syslog.txt
# ============================================================

param(
    [string]$Format = "ndjson",
    [string]$Output = "logs/siem_forward.json",
    [string]$Input = "logs/anomalous.json",
    [switch]$ListFormats,
    [switch]$Stats
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Get-Location).Path

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " AEGIS NIDS - Phase 33: SIEM Forwarder" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# List formats mode
# ============================================================

if ($ListFormats) {
    Write-Host "Supported output formats:" -ForegroundColor White
    Write-Host ""
    Write-Host "  ndjson  - Newline-Delimited JSON (default, for Elasticsearch/Logstash)" -ForegroundColor Cyan
    Write-Host "  cef     - Common Event Format (for Splunk/QRadar/ArcSight)" -ForegroundColor Cyan
    Write-Host "  syslog  - RFC 5424 Syslog (for rsyslog/syslog-ng)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\generate_siem_report.ps1 -Format <name>"
    exit 0
}

# ============================================================
# Read forensic log
# ============================================================

$inputPath = Join-Path $repoRoot $Input

if (-not (Test-Path $inputPath)) {
    Write-Host "[ERROR] Input log not found: $inputPath" -ForegroundColor Red
    Write-Host "  Run AEGIS first to generate events." -ForegroundColor Yellow
    exit 1
}

Write-Host "[STEP 1] Reading forensic log..." -ForegroundColor Cyan
Write-Host "  Input: $inputPath"

$events = @()
Get-Content $inputPath | ForEach-Object {
    $line = $_.Trim()
    if ($line) {
        try {
            $events += $line | ConvertFrom-Json
        } catch {
            # Skip invalid JSON lines
        }
    }
}

Write-Host "  [OK] Read $($events.Count) events" -ForegroundColor Green
Write-Host ""

# ============================================================
# Show statistics mode
# ============================================================

if ($Stats) {
    Write-Host "Event Statistics:" -ForegroundColor White
    Write-Host ""

    $stats = @{
        total = $events.Count
        byAttack = @{}
        bySeverity = @{}
        byStatus = @{}
    }

    foreach ($event in $events) {
        $atk = $event.attack_type
        $sev = $event.severity
        $sts = $event.status

        if ($atk) { $stats.byAttack[$atk] = ($stats.byAttack[$atk] + 1) }
        if ($sev) { $stats.bySeverity[$sev] = ($stats.bySeverity[$sev] + 1) }
        if ($sts) { $stats.byStatus[$sts] = ($stats.byStatus[$sts] + 1) }
    }

    Write-Host "  Total events: $($stats.total)" -ForegroundColor White
    Write-Host ""
    Write-Host "  By Attack Type:" -ForegroundColor Cyan
    $stats.byAttack.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        Write-Host "    $($_.Key): $($_.Value)" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "  By Severity:" -ForegroundColor Cyan
    $stats.bySeverity.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        Write-Host "    $($_.Key): $($_.Value)" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "  By Status:" -ForegroundColor Cyan
    $stats.byStatus.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        Write-Host "    $($_.Key): $($_.Value)" -ForegroundColor Gray
    }
    exit 0
}

# ============================================================
# Validate format
# ============================================================

$formats = @{
    "ndjson" = $true
    "cef" = $true
    "syslog" = $true
}

if (-not $formats.ContainsKey($Format.ToLower())) {
    Write-Host "[ERROR] Unknown format: $Format" -ForegroundColor Red
    Write-Host "  Available: ndjson, cef, syslog" -ForegroundColor Yellow
    exit 1
}

Write-Host "[STEP 2] Format: $Format" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# Format events
# ============================================================

function Format-EventNdjson {
    param($Event)
    return $Event | ConvertTo-Json -Compress -Depth 5
}

function Format-EventCef {
    param($Event)

    $cefSeverity = switch ($Event.severity) {
        "Critical" { "10" }
        "High" { "8" }
        "Medium" { "5" }
        "Low" { "3" }
        default { "3" }
    }

    $ruleId = if ($Event.rule_id) { $Event.rule_id } else { "UNKNOWN" }
    $attackType = if ($Event.attack_type) { $Event.attack_type } else { "UNKNOWN" }
    $srcIp = if ($Event.src_ip) { $Event.src_ip } else { "0.0.0.0" }
    $dstIp = if ($Event.dst_ip) { $Event.dst_ip } else { "0.0.0.0" }
    $srcPort = if ($Event.src_port) { $Event.src_port } else { 0 }
    $dstPort = if ($Event.dst_port) { $Event.dst_port } else { 0 }
    $protocol = if ($Event.protocol) { $Event.protocol } else { "TCP" }
    $policy = if ($Event.policy) { $Event.policy } else { "ALERT" }
    $status = if ($Event.status) { $Event.status } else { "DETECTED" }

    return "CEF:0|AEGIS|NIDS|5.0|$ruleId|$attackType|$cefSeverity|src=$srcIp dst=$dstIp spt=$srcPort dpt=$dstPort proto=$protocol policy=$policy status=$status"
}

function Format-EventSyslog {
    param($Event)

    $priority = 4  # warning severity, local0 facility
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    $attackType = if ($Event.attack_type) { $Event.attack_type } else { "UNKNOWN" }
    $srcIp = if ($Event.src_ip) { $Event.src_ip } else { "0.0.0.0" }
    $dstIp = if ($Event.dst_ip) { $Event.dst_ip } else { "0.0.0.0" }
    $severity = if ($Event.severity) { $Event.severity } else { "Unknown" }
    $status = if ($Event.status) { $Event.status } else { "DETECTED" }

    return "<$priority>1 $timestamp - AEGIS NIDS - - - attack_type=$attackType src=$srcIp dst=$dstIp severity=$severity status=$status"
}

Write-Host "[STEP 3] Formatting $($events.Count) events..." -ForegroundColor Cyan

$formattedLines = @()
$failed = 0

foreach ($event in $events) {
    try {
        $formatted = switch ($Format.ToLower()) {
            "ndjson" { Format-EventNdjson -Event $event }
            "cef" { Format-EventCef -Event $event }
            "syslog" { Format-EventSyslog -Event $event }
        }
        $formattedLines += $formatted
    } catch {
        $failed++
    }
}

Write-Host "  [OK] Formatted $($formattedLines.Count) events ($failed failed)" -ForegroundColor Green
Write-Host ""

# ============================================================
# Write output
# ============================================================

$outputPath = Join-Path $repoRoot $Output
$outputDir = Split-Path $outputPath -Parent

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
    Write-Host "  [OK] Created directory: $outputDir" -ForegroundColor Green
}

Write-Host "[STEP 4] Writing to: $outputPath" -ForegroundColor Cyan

# Write all formatted lines
$formattedLines | Out-File -FilePath $outputPath -Encoding UTF8 -NoNewline

# Add trailing newline
Add-Content -Path $outputPath -Value "" -Encoding UTF8

$size = (Get-Item $outputPath).Length
$sizeKB = [math]::Round($size / 1KB, 2)

Write-Host "  [OK] Written $($formattedLines.Count) lines ($sizeKB KB)" -ForegroundColor Green
Write-Host ""

# ============================================================
# SUMMARY
# ============================================================

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "SIEM FORWARD COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Input:    $inputPath ($($events.Count) events)"
Write-Host "  Output:   $outputPath ($($formattedLines.Count) lines, $sizeKB KB)"
Write-Host "  Format:   $Format"
Write-Host "  Failed:   $failed"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  - View output:      type $Output | Select-Object -First 5" -ForegroundColor Cyan
Write-Host "  - Forward to SIEM:  copy to SIEM collector or configure transport" -ForegroundColor Cyan
Write-Host "  - Re-run with format: .\generate_siem_report.ps1 -Format cef" -ForegroundColor Cyan
Write-Host ""
Write-Host "=== AEGIS NIDS PHASE 33 COMPLETE ===" -ForegroundColor Green
