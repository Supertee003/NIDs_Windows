# AEGIS NIDS - boot loader for the demand-start telemetry stack.
#
# Installed at <install>\scripts\boot-sequence.ps1 and registered as the
# AegisBootSequence task (AtStartup, SYSTEM, 20 s delay) by install-boot-task.ps1.
#
# Order matters (BOOT-RING-LOSS-001):
#   1. AegisWfp first - the daemon attests it once at startup;
#   2. AegisNids next  - it is DEMAND_START, so the task is its only loader;
#   3. AegisMinifilter last - the reader is already retrying the port (1 s
#      cadence), so the ring starts empty and the boot burst cannot overflow it.
#
# The task writes a probe under ProgramData so the boot result survives the
# interactive session that launched the reboot.

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $env:ProgramData 'AEGIS'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$log = Join-Path $logDir 'boot-sequence.log'

function Log([string]$m) {
    $line = "{0}  {1}" -f (Get-Date).ToString('HH:mm:ss'), $m
    Add-Content -Path $log -Value $line -Encoding utf8
}

function State([string]$svc) {
    try {
        $text = (& sc.exe query $svc 2>$null | Out-String)
        if ($text -match 'STATE\s+:\s+\d+\s+(\w+)') { return $Matches[1] }
    } catch { }
    return 'UNKNOWN'
}

function WaitState([string]$svc, [string]$want, [int]$seconds = 90) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if ((State $svc) -eq $want) { return $true }
        Start-Sleep -Milliseconds 750
    }
    return $false
}

function EnsureRunning([string]$svc, [int]$attempts = 10) {
    for ($i = 1; $i -le $attempts; $i++) {
        if ((State $svc) -eq 'RUNNING') { return $true }
        & sc.exe start $svc | Out-Null
        Start-Sleep -Seconds 3
    }
    return ((State $svc) -eq 'RUNNING')
}

function Sha([string]$p) {
    if (Test-Path -LiteralPath $p) { return (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }
    return 'MISSING'
}

Log 'boot sequence start'

# The filter manager / WFP engine may not be queryable the instant a startup
# task runs; wait for the service keys before driving them.
for ($i = 1; $i -le 20; $i++) {
    if ((State 'AegisWfp') -ne 'UNKNOWN') { break }
    Start-Sleep -Seconds 2
}

$wfpBefore = State 'AegisWfp'
$daemonBefore = State 'AegisNids'
$wfpOk = EnsureRunning 'AegisWfp'
Start-Sleep -Seconds 2

# If an older AUTO_START image somehow started before WFP, restart it after
# WFP so bridge_init attests the provider.
if ($daemonBefore -eq 'RUNNING' -and $wfpBefore -ne 'RUNNING') {
    Log 'daemon started before WFP; restarting it after WFP'
    & sc.exe stop AegisNids | Out-Null
    $null = WaitState 'AegisNids' 'STOPPED' 90
}
if ((State 'AegisNids') -ne 'RUNNING') {
    Log 'starting AegisNids (minifilter reader retries until its driver loads)'
    & sc.exe start AegisNids | Out-Null
    $null = WaitState 'AegisNids' 'RUNNING' 120
}
Log "AegisNids -> $(State 'AegisNids')"

$fimBefore = State 'AegisMinifilter'
$fimOk = EnsureRunning 'AegisMinifilter'
Log "drivers: AegisWfp $wfpBefore -> $(State 'AegisWfp'); AegisMinifilter $fimBefore -> $(State 'AegisMinifilter') (started after daemon)"

$probe = [ordered]@{
    checked_at = (Get-Date).ToString('s')
    root       = $root
    drivers    = [ordered]@{
        wfp_before = $wfpBefore; wfp_after = (State 'AegisWfp'); wfp_ok = $wfpOk
        daemon_before = $daemonBefore
        fim_before = $fimBefore; fim_after = (State 'AegisMinifilter'); fim_ok = $fimOk
    }
    services   = [ordered]@{}
    hashes     = [ordered]@{}
    scm_7031   = @()
}
foreach ($s in @('AegisNids','AegisAggregator','AegisWfp','AegisMinifilter')) {
    $probe.services[$s] = State $s
}
foreach ($p in @(
    (Join-Path $root 'runtime\aegis_nids.exe'),
    (Join-Path $root 'runtime\aegis_fim_helper.dll'),
    (Join-Path $root 'runtime\aegis_etw_helper.dll'),
    (Join-Path $root 'runtime\aegis_wfp_user.dll'),
    (Join-Path $env:WINDIR 'System32\drivers\aegis_wfp.sys'),
    (Join-Path $env:WINDIR 'System32\drivers\aegis_minifilter.sys')
)) { $probe.hashes[$p] = Sha $p }

$bootStart = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$probe.scm_7031 = @(Get-WinEvent -FilterHashtable @{ LogName='System'; ID=7031,7034; StartTime=$bootStart } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'AegisNids' } |
    ForEach-Object { $_.TimeCreated.ToString('s') })

$probe | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $logDir 'post-boot-probe.json') -Encoding utf8
Log 'boot sequence done; probe written'
exit 0
