[CmdletBinding()]
param(
    [string]$InstallRoot = "C:\Program Files\AEGIS NIDS",
    [string]$RepoRoot = "",
    [string]$ServiceName = "AegisNids",
    [string]$EvidenceDir = ""
)

# Deploys the local ReleaseFast build over the installed user-mode runtime and
# proves the postcondition that motivated the deploy: the service must load the
# canonical rule set instead of starting with zero rules from C:\Windows\System32.
#
# Scope (deliberately narrow):
#   - runtime\aegis_nids.exe + runtime\*.dll
#   - configs\Rules.json + configs\policies.json
# Untouched: the WFP driver, the AegisWfp service, WFP filters, firewall rules.
#
# Every replaced file is backed up into the evidence directory first, so the
# change is reversible without relying on the older full-install backup.

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}
$RepoRoot = (Resolve-Path $RepoRoot).Path
Set-Location $RepoRoot

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
if ([string]::IsNullOrWhiteSpace($EvidenceDir)) {
    $EvidenceDir = Join-Path $RepoRoot ("admin-evidence\deploy-{0}" -f $stamp)
}
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$backupRuntime = Join-Path $backupDir "runtime"
$backupConfig = Join-Path $backupDir "config"
New-Item -ItemType Directory -Force -Path $backupRuntime | Out-Null
New-Item -ItemType Directory -Force -Path $backupConfig | Out-Null

$sourceExe = Join-Path $RepoRoot "zig-out\bin\aegis_nids.exe"
if (-not (Test-Path $sourceExe -PathType Leaf)) {
    throw "Build first: missing $sourceExe (zig build -Doptimize=ReleaseFast)"
}

$runtime = Join-Path $InstallRoot "runtime"
$configDir = Join-Path $InstallRoot "configs"
if (-not (Test-Path $runtime)) { throw "Installed runtime not found: $runtime" }

$runtimeFiles = @("aegis_nids.exe", "aegis_pep.dll", "aegis_ipc.dll",
                  "aegis_wfp_user.dll", "aegis_etw_helper.dll", "aegis_fim_helper.dll")
$configFiles = @("Rules.json", "policies.json")

function Get-FileDigest([string]$Path) {
    if (-not (Test-Path $Path -PathType Leaf)) { return $null }
    return (Get-FileHash $Path -Algorithm SHA256).Hash
}

function Get-StateSnapshot([string]$Label) {
    $snapshot = [ordered]@{ label = $Label; timestamp_utc = (Get-Date).ToUniversalTime().ToString("o") }
    $runtimeHashes = [ordered]@{}
    foreach ($name in $runtimeFiles) {
        $runtimeHashes[$name] = Get-FileDigest (Join-Path $runtime $name)
    }
    $snapshot.runtime = $runtimeHashes
    $configHashes = [ordered]@{}
    foreach ($name in $configFiles) {
        $configHashes[$name] = Get-FileDigest (Join-Path $configDir $name)
    }
    $snapshot.configs = $configHashes
    $service = sc.exe query $ServiceName 2>$null | Out-String
    $snapshot.service_query = ($service -replace "`r`n", " | ").Trim()
    $snapshot | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $EvidenceDir "$Label.json") -Encoding UTF8
    return $snapshot
}

function Invoke-HealthJson([string]$Name) {
    $raw = (& python (Join-Path $RepoRoot "tools\aegisctl.py") @("health", "--json") 2>&1 | Out-String).Trim()
    $exitCode = $LASTEXITCODE
    Set-Content -Path (Join-Path $EvidenceDir "$Name.raw.txt") -Value $raw -Encoding UTF8
    try { $json = $raw | ConvertFrom-Json } catch { $json = $null }
    if ($null -ne $json) {
        $json | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $EvidenceDir "$Name.json") -Encoding UTF8
    }
    return [pscustomobject]@{ Json = $json; ExitCode = $exitCode; Raw = $raw }
}

$before = Get-StateSnapshot "before"

# 1. Stop the service and wait for a real STOPPED postcondition.
sc.exe stop $ServiceName | Out-Null
$stopped = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    $state = (sc.exe query $ServiceName | Select-String "STATE" | Out-String)
    if ($state -match "STOPPED") { $stopped = $true; break }
}
if (-not $stopped) {
    throw "Service $ServiceName did not reach STOPPED; aborting without changing files"
}

# 2. Back up every file that will be replaced, preserving names so the
# backup directory itself is a working rollback source.
foreach ($name in $runtimeFiles) {
    $path = Join-Path $runtime $name
    if (Test-Path $path -PathType Leaf) {
        Copy-Item $path (Join-Path $backupRuntime $name) -Force
    }
}
foreach ($name in $configFiles) {
    $path = Join-Path $configDir $name
    if (Test-Path $path -PathType Leaf) {
        Copy-Item $path (Join-Path $backupConfig $name) -Force
    }
}

# 3. Copy the new runtime and configs. Fail closed on any missing build
# artifact: a partial copy would mix new and old binary versions.
$missingSources = [System.Collections.Generic.List[string]]::new()
foreach ($name in $runtimeFiles) {
    $src = Join-Path $RepoRoot ("zig-out\bin\{0}" -f $name)
    if (Test-Path $src -PathType Leaf) {
        Copy-Item $src (Join-Path $runtime $name) -Force
    } else {
        $missingSources.Add($src)
    }
}
foreach ($name in $configFiles) {
    $src = Join-Path $RepoRoot ("configs\{0}" -f $name)
    if (Test-Path $src -PathType Leaf) {
        Copy-Item $src (Join-Path $configDir $name) -Force
    } else {
        $missingSources.Add($src)
    }
}
if ($missingSources.Count -gt 0) {
    throw ("Build incomplete, refusing partial deploy. Missing: " + ($missingSources -join "; "))
}

# 4. Start the service.
sc.exe start $ServiceName | Out-Null

# 5. Prove the postcondition: rules are loaded, not zero.
$health = $null
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 2
    $probe = Invoke-HealthJson ("health-attempt-{0:d2}" -f $i)
    if ($null -ne $probe.Json) { $health = $probe.Json; break }
}
if ($null -eq $health) {
    throw "Service started but the control pipe never answered a health query"
}

$after = Get-StateSnapshot "after"

$rulesLoaded = 0
if ($null -ne $health.rules_loaded) { $rulesLoaded = [int]$health.rules_loaded }
$policiesLoaded = 0
if ($null -ne $health.policies_loaded) { $policiesLoaded = [int]$health.policies_loaded }

$failures = [System.Collections.Generic.List[string]]::new()
if ($rulesLoaded -le 0) { $failures.Add("rules_loaded=$rulesLoaded after deploy") }
$expectedRules = (Get-Content (Join-Path $RepoRoot "configs\Rules.json") -Raw | ConvertFrom-Json).nids_rules.Count
if ($rulesLoaded -ne $expectedRules) { $failures.Add("rules_loaded=$rulesLoaded, expected $expectedRules (configs/Rules.json)") }
if ($policiesLoaded -ne 6) { $failures.Add("policies_loaded=$policiesLoaded, expected 6") }

$result = [ordered]@{
    proof = "runtime_deploy"
    passed = ($failures.Count -eq 0)
    evidence_dir = $EvidenceDir
    install_root = $InstallRoot
    service = $ServiceName
    deployed_exe_sha256 = Get-FileDigest (Join-Path $runtime "aegis_nids.exe")
    previous_exe_sha256 = $before.runtime["aegis_nids.exe"]
    rules_loaded = $rulesLoaded
    policies_loaded = $policiesLoaded
    health_state = $health.state
    health_degraded = $health.degraded
    failures = @($failures)
    rollback = "Copy-Item '$backupRuntime\*' '$runtime' -Force; Copy-Item '$backupConfig\*' '$configDir' -Force"
}
$result | ConvertTo-Json -Depth 10 | Tee-Object -FilePath (Join-Path $EvidenceDir "result.json")

if ($failures.Count -gt 0) {
    throw ("RUNTIME_DEPLOY_FAIL: " + ($failures -join "; "))
}
Write-Host "RUNTIME_DEPLOY=PASS (rules_loaded=$rulesLoaded policies_loaded=$policiesLoaded)" -ForegroundColor Green
