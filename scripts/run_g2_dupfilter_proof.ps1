# Detection-only host proof runner (elevated, lab-only).
#
# Retired host-effect proof, replaced by RETIRE-HOST-EFFECT-001 (issue #25).
# This runner no longer installs or removes a WFP filter: the confirmed product
# decision is detection-only. It drives the direct PEP harness with identical
# BLOCK and QUARANTINE requests and requires both to come back as ESCALATE
# reason=8 with filter_id=0, i.e. evidence for human review and no host effect.
#
# Requires Administrator and the pinned signed driver already loaded. It does
# NOT open the production prevention gate, change daemon policy, or restart a
# service. All hashes are operator-supplied so a stale DLL/driver cannot be
# mistaken for the evidence candidate.
#
# Usage (elevated):
#   powershell -NoProfile -ExecutionPolicy Bypass -File `
#     scripts/run_g2_dupfilter_proof.ps1 `
#     -ExpectedDriverSha256 <loaded-signed-sha256> `
#     -ExpectedPepSha256 <aegis_pep.dll-sha256> `
#     [-ExpectedBridgeSha256 <aegis_wfp_user.dll-sha256>]

param(
    [Parameter(Mandatory = $true)]
    [string]$ExpectedDriverSha256,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedPepSha256,

    [string]$ExpectedBridgeSha256 = "",

    [string]$OutDir = "admin-evidence\g2-dupfilter-20261024"
)

$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo

$out = if ([System.IO.Path]::IsPathRooted($OutDir)) {
    $OutDir
} else {
    Join-Path $repo $OutDir
}

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "host proof requires an elevated Administrator shell"
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Resolve-ServiceImagePath {
    param([string]$ServiceName)
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $raw = (Get-ItemProperty -Path $serviceKey -Name ImagePath -ErrorAction Stop).ImagePath
    if (-not $raw) { throw "service $ServiceName has no ImagePath" }
    $path = $raw.Trim()
    if ($path.StartsWith('"')) {
        $endQuote = $path.IndexOf('"', 1)
        if ($endQuote -lt 1) { throw "malformed ImagePath: $raw" }
        $path = $path.Substring(1, $endQuote - 1)
    } else {
        # Strip unquoted command arguments, but keep spaces in a path.
        $match = [regex]::Match($path, '^(?<path>.+?\.sys)(?:\s|$)', 'IgnoreCase')
        if ($match.Success) { $path = $match.Groups['path'].Value }
    }
    $path = $path -replace '^\\\?\?\\', ''
    $path = [System.Environment]::ExpandEnvironmentVariables($path)
    if ($path -match '^\\SystemRoot\\(?<rest>.+)$') {
        $path = Join-Path $env:SystemRoot $Matches['rest']
    } elseif (-not [System.IO.Path]::IsPathRooted($path)) {
        $path = Join-Path $env:SystemRoot $path
    }
    return [System.IO.Path]::GetFullPath($path)
}

$driverSvc = Get-Service -Name "AegisWfp" -ErrorAction SilentlyContinue
if (-not $driverSvc) { throw "service not found: AegisWfp" }
if ($driverSvc.Status -ne "Running") {
    throw "AegisWfp is $($driverSvc.Status), expected Running"
}
$loadedDriver = Resolve-ServiceImagePath "AegisWfp"
if (-not (Test-Path $loadedDriver)) {
    throw "loaded driver path not found: $loadedDriver"
}
$driverHash = Get-Sha256 $loadedDriver
if ($driverHash -ne $ExpectedDriverSha256.ToUpperInvariant()) {
    throw "loaded driver hash mismatch: $driverHash != $ExpectedDriverSha256"
}
$driverSig = Get-AuthenticodeSignature $loadedDriver
if ($driverSig.Status -ne "Valid") {
    throw "loaded driver signature is $($driverSig.Status), not Valid"
}

$pep = Join-Path $repo "target\release\aegis_pep.dll"
if (-not (Test-Path $pep)) { throw "PEP DLL not found: $pep" }
$pepHash = Get-Sha256 $pep
if ($pepHash -ne $ExpectedPepSha256.ToUpperInvariant()) {
    throw "PEP hash mismatch: $pepHash != $ExpectedPepSha256"
}

$bridgeCandidates = @(
    (Join-Path $repo "build\Release\aegis_wfp_user.dll"),
    (Join-Path $repo "build\wfp-user\Release\aegis_wfp_user.dll")
)
$bridge = $bridgeCandidates |
    Where-Object { Test-Path $_ } |
    Select-Object -First 1
if (-not $bridge) {
    throw "WFP bridge DLL not found in: $($bridgeCandidates -join ', ')"
}
$bridgeHash = Get-Sha256 $bridge
if ($ExpectedBridgeSha256 -and
    $bridgeHash -ne $ExpectedBridgeSha256.ToUpperInvariant()) {
    throw "bridge hash mismatch: $bridgeHash != $ExpectedBridgeSha256"
}

New-Item -ItemType Directory -Force -Path $out | Out-Null
$log = Join-Path $out "host-run.txt"
$resultPath = Join-Path $out "host-run-result.json"
$env:AEGIS_RUN_WFP_HOST_TESTS = "1"
$env:AEGIS_DRIVER_PATH = $loadedDriver
$env:AEGIS_EXPECTED_DRIVER_SHA256 = $driverHash
$env:AEGIS_EXPECTED_PEP_SHA256 = $pepHash
$env:AEGIS_EXPECTED_BRIDGE_SHA256 = $bridgeHash

Write-Host "[g2] repo=$repo"
Write-Host "[g2] driver_path=$loadedDriver"
Write-Host "[g2] driver_sha256=$driverHash"
Write-Host "[g2] pep_sha256=$pepHash"
Write-Host "[g2] bridge=$bridge"
Write-Host "[g2] bridge_sha256=$bridgeHash"
Write-Host "[g2] transcript=$log"

python -m pytest `
    "tests/wfp/test_t11_windows_host.py::test_rust_pep_reports_detection_only_for_quarantine_on_windows" `
    -q -s 2>&1 | Tee-Object -FilePath $log

$rc = $LASTEXITCODE
$text = if (Test-Path $log) { Get-Content -Raw $log } else { "" }
# pytest writes CRLF on Windows; normalize so a `$`-anchored marker can never
# fail only because of the carriage return.
$text = $text -replace "`r`n", "`n" -replace "`r", "`n"

$expectedDriver = [regex]::Escape($driverHash)
$expectedPep = [regex]::Escape($pepHash)
$expectedBridge = [regex]::Escape($bridgeHash)
$markers = [ordered]@{
    driver_hash = [bool]($text -match "(?m)^ARTIFACT_DRIVER_SHA256=$expectedDriver$")
    pep_hash = [bool]($text -match "(?m)^ARTIFACT_PEP_SHA256=$expectedPep$")
    bridge_hash = [bool]($text -match "(?m)^ARTIFACT_BRIDGE_LOADED_SHA256=$expectedBridge$")
    bridge_loaded = [bool]($text -match "(?m)^BRIDGE_LOADED_PATH=")
    detection_only_quarantine = [bool]($text -match "DETECTION_ONLY_QUARANTINE=true")
    detection_only_no_filter = [bool]($text -match "DETECTION_ONLY_NO_FILTER=true")
    no_skip = -not [bool]($text -match "(?m)^\d+ skipped|skipped in")
}

$failures = @()
if ($rc -ne 0) { $failures += "pytest exit=$rc" }
foreach ($name in $markers.Keys) {
    if (-not $markers[$name]) { $failures += "missing/false marker: $name" }
}
if ($failures.Count -gt 0) {
    Write-Host "[g2] FAIL: $($failures -join '; ')" -ForegroundColor Red
}

$result = [ordered]@{
    started_at = (Get-Date).ToString("o")
    repo = $repo
    driver_path = $loadedDriver
    driver_sha256 = $driverHash
    driver_signature = [string]$driverSig.Status
    pep_path = $pep
    pep_sha256 = $pepHash
    bridge_path = $bridge
    bridge_sha256 = $bridgeHash
    pytest_exit = $rc
    markers = $markers
    failures = $failures
    transcript = $log
    finished_at = (Get-Date).ToString("o")
}
$result |
    ConvertTo-Json -Depth 6 |
    Out-File -FilePath $resultPath -Encoding utf8

Write-Host "[g2] pytest exit=$rc"
if ($failures.Count -gt 0) { exit 1 }
Write-Host "[g2] PROOF PASS: block/quarantine are detection-only with no host effect"
exit 0
