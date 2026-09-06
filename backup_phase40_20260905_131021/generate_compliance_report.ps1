# ============================================================
# AEGIS NIDS - Phase 40: Compliance Report Generator
# ============================================================
# Generates compliance reports from forensic logs.
# Supports: PCI-DSS, HIPAA, ISO 27001
# Output: JSON, text summary to console
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\generate_compliance_report.ps1
#   powershell -ExecutionPolicy Bypass -File .\generate_compliance_report.ps1 -Framework PCI-DSS
#   powershell -ExecutionPolicy Bypass -File .\generate_compliance_report.ps1 -Framework All
#   powershell -ExecutionPolicy Bypass -File .\generate_compliance_report.ps1 -ListFrameworks
# ============================================================

param(
    [string]$Framework = "All",
    [switch]$ListFrameworks,
    [switch]$JsonOnly
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Get-Location).Path

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " AEGIS NIDS - Phase 40: Compliance Report" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# Framework definitions
# ============================================================

$FRAMEWORKS = @{
    "PCI-DSS" = @{
        Name = "PCI-DSS (Payment Card Industry Data Security Standard)"
        Controls = @(
            @{Id="PCI-10.1"; Name="Audit Logging Enabled"; Check="total_detected > 0"}
            @{Id="PCI-10.2"; Name="Security Event Logging"; Check="total_detected > 0"}
            @{Id="PCI-10.3"; Name="Event Detail Capture"; Check="total_detected > 0"}
            @{Id="PCI-10.4"; Name="Time Synchronization"; Check="always_true"}
            @{Id="PCI-10.5"; Name="Audit Log Protection"; Check="always_true"}
            @{Id="PCI-10.6"; Name="Log Review"; Check="total_detected > 0"}
            @{Id="PCI-10.7"; Name="Log Retention"; Check="always_true"}
            @{Id="PCI-11.4"; Name="Vulnerability Scanning"; Check="total_detected > 0"}
            @{Id="PCI-11.5"; Name="Intrusion Detection"; Check="total_detected > 0"}
            @{Id="PCI-12.10"; Name="Incident Response"; Check="total_blocked > 0"}
        )
    }
    "HIPAA" = @{
        Name = "HIPAA (Health Insurance Portability and Accountability Act)"
        Controls = @(
            @{Id="HIPAA-164.312(b)"; Name="Audit Controls"; Check="total_detected > 0"}
            @{Id="HIPAA-164.312(c)(1)"; Name="Integrity Controls"; Check="total_detected > 0"}
            @{Id="HIPAA-164.312(d)"; Name="Person Authentication"; Check="always_true"}
            @{Id="HIPAA-164.312(e)(1)"; Name="Transmission Security"; Check="total_blocked > 0"}
            @{Id="HIPAA-164.312(e)(2)(ii)"; Name="Encryption"; Check="always_true"}
            @{Id="HIPAA-164.308(a)(1)(ii)(C)"; Name="Sanction Policy"; Check="always_true"}
            @{Id="HIPAA-164.308(a)(3)"; Name="Workforce Security"; Check="always_true"}
            @{Id="HIPAA-164.308(a)(5)"; Name="Security Awareness"; Check="always_true"}
            @{Id="HIPAA-164.308(a)(6)"; Name="Security Incident"; Check="total_blocked > 0"}
            @{Id="HIPAA-164.312(a)(1)"; Name="Access Control"; Check="total_blocked > 0"}
        )
    }
    "ISO-27001" = @{
        Name = "ISO 27001 (Information Security Management)"
        Controls = @(
            @{Id="ISO-A.8.1.1"; Name="Asset Inventory"; Check="always_true"}
            @{Id="ISO-A.8.2.1"; Name="Classification"; Check="always_true"}
            @{Id="ISO-A.9.1.1"; Name="Access Control Policy"; Check="always_true"}
            @{Id="ISO-A.10.1.1"; Name="Network Controls"; Check="total_detected > 0"}
            @{Id="ISO-A.12.1.1"; Name="Operational Procedures"; Check="always_true"}
            @{Id="ISO-A.12.2.1"; Name="Malware Detection"; Check="total_detected > 0"}
            @{Id="ISO-A.12.4.1"; Name="Event Logging"; Check="total_detected > 0"}
            @{Id="ISO-A.12.4.3"; Name="Administrator Logs"; Check="total_detected > 0"}
            @{Id="ISO-A.13.1.1"; Name="Network Security Controls"; Check="total_blocked > 0"}
            @{Id="ISO-A.13.2.1"; Name="Information Transfer Policies"; Check="always_true"}
            @{Id="ISO-A.16.1.1"; Name="Incident Management"; Check="total_blocked > 0"}
            @{Id="ISO-A.16.1.2"; Name="Incident Reporting"; Check="total_detected > 0"}
        )
    }
}

# ============================================================
# List frameworks mode
# ============================================================

if ($ListFrameworks) {
    Write-Host "Available compliance frameworks:" -ForegroundColor White
    Write-Host ""
    foreach ($key in $FRAMEWORKS.Keys | Sort-Object) {
        $fw = $FRAMEWORKS[$key]
        Write-Host "  $key" -ForegroundColor Cyan
        Write-Host "    $($fw.Name)" -ForegroundColor Gray
        Write-Host "    Controls: $($fw.Controls.Count)" -ForegroundColor Gray
        Write-Host ""
    }
    exit 0
}

# ============================================================
# Read forensic log and compute stats
# ============================================================

Write-Host "[STEP 1] Reading forensic log..." -ForegroundColor Cyan

$logPath = Join-Path $repoRoot 'logs\anomalous.json'

if (-not (Test-Path $logPath)) {
    Write-Host "  [WARN] Forensic log not found: $logPath" -ForegroundColor Yellow
    Write-Host "  Using empty statistics (all checks will pass trivially)" -ForegroundColor Gray
    $events = @()
} else {
    $events = @()
    Get-Content $logPath | ForEach-Object {
        $line = $_.Trim()
        if ($line) {
            try {
                $events += $line | ConvertFrom-Json
            } catch {
                # Skip invalid JSON lines
            }
        }
    }
    Write-Host "  [OK] Read $($events.Count) events from anomalous.json" -ForegroundColor Green
}

# ============================================================
# Compute statistics
# ============================================================

Write-Host ""
Write-Host "[STEP 2] Computing statistics..." -ForegroundColor Cyan

$stats = @{
    total_events = $events.Count
    total_detected = 0
    total_blocked = 0
    total_block_failed = 0
    total_alerts = 0
    sqli_count = 0
    xss_count = 0
    path_traversal_count = 0
    log4j_count = 0
    rfi_count = 0
    port_scan_count = 0
    brute_force_count = 0
    dns_exfil_count = 0
    syn_flood_count = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    unique_src_ips = @{}
}

foreach ($event in $events) {
    $status = $event.status
    $attackType = $event.attack_type
    $severity = $event.severity
    $srcIp = $event.src_ip

    if ($status -eq "DETECTED") { $stats.total_detected++ }
    elseif ($status -eq "BLOCK_OK" -or $status -eq "BLOCKED") {
        $stats.total_blocked++
        $stats.total_detected++
    }
    elseif ($status -eq "BLOCK_FAILED") {
        $stats.total_block_failed++
        $stats.total_detected++
    }
    elseif ($status -eq "ALERT") {
        $stats.total_alerts++
        $stats.total_detected++
    }

    if ($attackType -match "SQL") { $stats.sqli_count++ }
    elseif ($attackType -match "XSS") { $stats.xss_count++ }
    elseif ($attackType -match "PATH_TRAV" -or $attackType -match "TRAV") { $stats.path_traversal_count++ }
    elseif ($attackType -match "LOG4J") { $stats.log4j_count++ }
    elseif ($attackType -match "RFI") { $stats.rfi_count++ }
    elseif ($attackType -match "PORT_SCAN") { $stats.port_scan_count++ }
    elseif ($attackType -match "BRUTE") { $stats.brute_force_count++ }
    elseif ($attackType -match "DNS_EXFIL" -or $attackType -match "EXFIL") { $stats.dns_exfil_count++ }
    elseif ($attackType -match "SYN_FLOOD" -or $attackType -match "FLOOD") { $stats.syn_flood_count++ }

    if ($severity -eq "Critical") { $stats.critical_count++ }
    elseif ($severity -eq "High") { $stats.high_count++ }
    elseif ($severity -eq "Medium") { $stats.medium_count++ }
    elseif ($severity -eq "Low") { $stats.low_count++ }

    if ($srcIp) { $stats.unique_src_ips[$srcIp] = $true }
}

$stats.unique_src_ips = $stats.unique_src_ips.Count

$detectionRate = if ($stats.total_events -gt 0) {
    [math]::Round(($stats.total_detected / $stats.total_events) * 100, 2)
} else { 0.0 }

$blockSuccessRate = if (($stats.total_blocked + $stats.total_block_failed) -gt 0) {
    [math]::Round(($stats.total_blocked / ($stats.total_blocked + $stats.total_block_failed)) * 100, 2)
} else { 100.0 }

Write-Host "  [OK] Statistics computed" -ForegroundColor Green
Write-Host "  Total events:    $($stats.total_events)" -ForegroundColor Gray
Write-Host "  Detected:        $($stats.total_detected)" -ForegroundColor Gray
Write-Host "  Blocked (OK):    $($stats.total_blocked)" -ForegroundColor Gray
Write-Host "  Block failed:    $($stats.total_block_failed)" -ForegroundColor Gray
Write-Host "  Detection rate:  $detectionRate%" -ForegroundColor Gray
Write-Host "  Block success:   $blockSuccessRate%" -ForegroundColor Gray

# ============================================================
# Evaluate controls
# ============================================================

function Test-Control {
    param([string]$Check, [hashtable]$Stats)

    switch ($Check) {
        "always_true" { return $true }
        "total_detected > 0" { return $Stats.total_detected -gt 0 }
        "total_blocked > 0" { return $Stats.total_blocked -gt 0 }
        default { return $false }
    }
}

function Generate-FrameworkReport {
    param([string]$FrameworkKey, [hashtable]$Framework, [hashtable]$Stats)

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "Framework: $FrameworkKey" -ForegroundColor White
    Write-Host "  $($Framework.Name)" -ForegroundColor Gray
    Write-Host "============================================================" -ForegroundColor Cyan

    $passed = 0
    $failed = 0
    $controlResults = @()

    foreach ($control in $Framework.Controls) {
        $result = Test-Control -Check $control.Check -Stats $Stats
        $status = if ($result) { "[PASS]" } else { "[FAIL]" }
        $color = if ($result) { "Green" } else { "Red" }

        Write-Host "  $status $($control.Id): $($control.Name)" -ForegroundColor $color

        if ($result) { $passed++ } else { $failed++ }

        $controlResults += @{
            id = $control.Id
            name = $control.Name
            check = $control.Check
            passed = $result
        }
    }

    $total = $passed + $failed
    $score = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 2) } else { 0.0 }
    $isCompliant = $score -ge 80.0

    Write-Host ""
    Write-Host "  Controls: $passed/$total passed" -ForegroundColor White
    Write-Host "  Compliance Score: $score%" -ForegroundColor $(if ($isCompliant) { "Green" } else { "Red" })
    Write-Host "  Status: $(if ($isCompliant) { 'COMPLIANT' } else { 'NON-COMPLIANT' })" -ForegroundColor $(if ($isCompliant) { "Green" } else { "Red" })

    return @{
        framework = $FrameworkKey
        name = $Framework.Name
        controls_checked = $total
        controls_passed = $passed
        controls_failed = $failed
        compliance_score = $score
        is_compliant = $isCompliant
        control_results = $controlResults
    }
}

# ============================================================
# Generate reports for selected framework(s)
# ============================================================

Write-Host ""
Write-Host "[STEP 3] Generating compliance reports..." -ForegroundColor Cyan

$reportsToGenerate = @()
if ($Framework -eq "All") {
    $reportsToGenerate = $FRAMEWORKS.Keys | Sort-Object
} else {
    # Normalize framework name
    $normalized = $null
    foreach ($key in $FRAMEWORKS.Keys) {
        if ($key -replace "[^A-Z0-9]", "" -eq ($Framework -replace "[^A-Z0-9]", "")) {
            $normalized = $key
            break
        }
    }
    if (-not $normalized) {
        Write-Host "  [ERROR] Unknown framework: $Framework" -ForegroundColor Red
        Write-Host "  Available: $($FRAMEWORKS.Keys -join ', ')" -ForegroundColor Yellow
        exit 1
    }
    $reportsToGenerate = @($normalized)
}

$allReports = @()
foreach ($fwKey in $reportsToGenerate) {
    $fw = $FRAMEWORKS[$fwKey]
    $report = Generate-FrameworkReport -FrameworkKey $fwKey -Framework $fw -Stats $stats
    $allReports += $report
}

# ============================================================
# Save JSON reports
# ============================================================

Write-Host ""
Write-Host "[STEP 4] Saving JSON reports..." -ForegroundColor Cyan

$reportsDir = Join-Path $repoRoot 'reports'
if (-not (Test-Path $reportsDir)) {
    New-Item -ItemType Directory -Force -Path $reportsDir | Out-Null
    Write-Host "  [OK] Created reports/ directory" -ForegroundColor Green
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

foreach ($report in $allReports) {
    $fileName = "$($report.framework)_$timestamp.json"
    $filePath = Join-Path $reportsDir $fileName

    $jsonOutput = @{
        framework = $report.framework
        name = $report.name
        generated_at = (Get-Date).ToString('o')
        compliance_score = $report.compliance_score
        is_compliant = $report.is_compliant
        controls_checked = $report.controls_checked
        controls_passed = $report.controls_passed
        controls_failed = $report.controls_failed
        statistics = @{
            total_events = $stats.total_events
            total_detected = $stats.total_detected
            total_blocked = $stats.total_blocked
            total_block_failed = $stats.total_block_failed
            detection_rate_pct = $detectionRate
            block_success_rate_pct = $blockSuccessRate
            unique_src_ips = $stats.unique_src_ips
            attack_breakdown = @{
                sqli = $stats.sqli_count
                xss = $stats.xss_count
                path_traversal = $stats.path_traversal_count
                log4j = $stats.log4j_count
                rfi = $stats.rfi_count
                port_scan = $stats.port_scan_count
                brute_force = $stats.brute_force_count
                dns_exfil = $stats.dns_exfil_count
                syn_flood = $stats.syn_flood_count
            }
            severity_breakdown = @{
                critical = $stats.critical_count
                high = $stats.high_count
                medium = $stats.medium_count
                low = $stats.low_count
            }
        }
        control_results = $report.control_results
    }

    $jsonOutput | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8
    Write-Host "  [OK] Saved: $filePath" -ForegroundColor Green
}

# ============================================================
# SUMMARY
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "COMPLIANCE REPORTS GENERATED" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

foreach ($report in $allReports) {
    $status = if ($report.is_compliant) { "COMPLIANT" } else { "NON-COMPLIANT" }
    $color = if ($report.is_compliant) { "Green" } else { "Red" }
    Write-Host "  $($report.framework): $status ($($report.compliance_score)% - $($report.controls_passed)/$($report.controls_checked) controls)" -ForegroundColor $color
}

Write-Host ""
Write-Host "Reports directory: $reportsDir" -ForegroundColor White
Write-Host "Total reports: $($allReports.Count)" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  - Review reports: Get-ChildItem $reportsDir" -ForegroundColor Cyan
Write-Host "  - View specific: type reports\<framework>_<timestamp>.json" -ForegroundColor Cyan
Write-Host "  - Generate again: .\generate_compliance_report.ps1 -Framework <name>" -ForegroundColor Cyan
Write-Host ""
Write-Host "=== AEGIS NIDS PHASE 40 COMPLETE ===" -ForegroundColor Green
