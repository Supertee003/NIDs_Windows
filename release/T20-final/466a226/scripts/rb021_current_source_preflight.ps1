[CmdletBinding()]
param(
    [string]$ExpectedKaliIp = '192.168.126.10',
    [string]$ExpectedVictimIp = '192.168.126.20',
    [string]$ExpectedNidsIp = '192.168.126.1',
    [string]$BuildRuntimePath = 'zig-out\bin\aegis_nids.exe',
    [string]$InstalledRuntimePath = 'C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe',
    [string]$ProofOutput = ''
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
if (-not $ProofOutput) {
    $ProofOutput = Join-Path $repo ('admin-evidence\rb021-preflight-' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
New-Item -ItemType Directory -Force -Path $ProofOutput | Out-Null
$recordPath = Join-Path $ProofOutput 'preflight.json'
$failures = [System.Collections.Generic.List[string]]::new()
$checks = [ordered]@{}

function Check([string]$Name, [bool]$Ok, [string]$Detail) {
    $checks[$Name] = [ordered]@{ passed = $Ok; detail = $Detail }
    if (-not $Ok) { $failures.Add("${Name}: $Detail") }
}

function Hash([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
Check 'elevated_session' $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) 'Administrator token is required for the bounded RB-021 service/interface round-trip.'

$gitHead = (& git -c "safe.directory=$repo" -C $repo rev-parse HEAD 2>$null).Trim()
$buildSourcePaths = @('src', 'rust-src', 'shield', 'nose', 'go', 'brain', 'drivers', 'shared', 'build.zig', 'build.zig.zon', 'CMakeLists.txt', 'Cargo.toml', 'go.mod', 'ts_policy')
$buildSource = (& git -c "safe.directory=$repo" -C $repo log -1 --format=%H -- $buildSourcePaths 2>$null).Trim()
$manifest = $null
if (Test-Path (Join-Path $repo 'build_manifest.json')) {
    try { $manifest = Get-Content (Join-Path $repo 'build_manifest.json') -Raw | ConvertFrom-Json } catch {}
}
$manifestSource = if ($manifest -and $manifest.source_commit) { [string]$manifest.source_commit } else { '' }
Check 'source_commit_available' ($gitHead -match '^[0-9a-f]{40}$') "git HEAD=$gitHead"
Check 'build_source_available' ($buildSource -match '^[0-9a-f]{40}$') "build_source_commit=$buildSource"
Check 'build_manifest_source' (($manifestSource -ne '') -and $buildSource.StartsWith($manifestSource)) "build_manifest.source_commit=$manifestSource; build_source_commit=$buildSource; records_head=$gitHead"

$buildHash = Hash (Join-Path $repo $BuildRuntimePath)
$installedHash = Hash $InstalledRuntimePath
Check 'build_runtime_present' ($null -ne $buildHash) "build=$BuildRuntimePath sha256=$buildHash"
Check 'installed_runtime_present' ($null -ne $installedHash) "installed=$InstalledRuntimePath sha256=$installedHash"
Check 'installed_matches_current_build' (($null -ne $buildHash) -and ($buildHash -eq $installedHash)) "build_sha256=$buildHash; installed_sha256=$installedHash"

$service = Get-Service -Name 'AegisNids' -ErrorAction SilentlyContinue
Check 'aegis_service_running' ($null -ne $service -and $service.Status -eq 'Running') "service_status=$($service.Status)"

$ip = Get-NetIPAddress -IPAddress $ExpectedNidsIp -ErrorAction SilentlyContinue | Select-Object -First 1
$adapter = if ($ip) { Get-NetAdapter -InterfaceIndex $ip.InterfaceIndex -ErrorAction SilentlyContinue } else { $null }
Check 'nids_vmnet_ip' ($null -ne $ip) "expected_nids_ip=$ExpectedNidsIp interface=$($ip.InterfaceAlias)"
Check 'nids_vmnet_link_up' ($null -ne $adapter -and $adapter.Status -eq 'Up') "interface_status=$($adapter.Status) interface=$($ip.InterfaceAlias)"

$machinePin = [Environment]::GetEnvironmentVariable('AEGIS_DAEMON_IFACE', 'Machine')
Check 'daemon_vmnet_pin_present' (-not [string]::IsNullOrWhiteSpace($machinePin)) "AEGIS_DAEMON_IFACE=$machinePin"

$daemonProcess = @(Get-Process -Name 'aegis_nids' -ErrorAction SilentlyContinue | Select-Object -First 1)
$daemonPid = if ($daemonProcess.Count -gt 0) { [int]$daemonProcess[0].Id } else { 0 }
$noseProcess = @(Get-Process -Name 'aegis-nose' -ErrorAction SilentlyContinue | Select-Object -First 1)
$nosePid = if ($noseProcess.Count -gt 0) { [int]$noseProcess[0].Id } else { 0 }
$dumpScript = Join-Path $repo 'admin-evidence\lab-rate-e5-20261020\dump-daemon-env.ps1'
$processPin = ''
$noseMachinePin = [Environment]::GetEnvironmentVariable('AEGIS_NOSE_IFACE', 'Machine')
$noseProcessPin = ''
if (($daemonPid -gt 0) -and (Test-Path -LiteralPath $dumpScript)) {
    $dump = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $dumpScript -TargetPid $daemonPid -NosePid $nosePid 2>&1)
    $pinLine = $dump | ForEach-Object { $_.ToString() } | Where-Object { $_ -match '^AEGIS_DAEMON_IFACE=' } | Select-Object -First 1
    if ($pinLine) { $processPin = ($pinLine -split '=', 2)[1] }
    $nosePinLine = $dump | ForEach-Object { $_.ToString() } | Where-Object { $_ -match '^AEGIS_NOSE_IFACE=' } | Select-Object -First 1
    if ($nosePinLine) { $noseProcessPin = ($nosePinLine -split '=', 2)[1] }
}
Check 'daemon_process_pin_matches' (($daemonPid -gt 0) -and ($processPin -eq $machinePin) -and (-not [string]::IsNullOrWhiteSpace($processPin))) "daemon_pid=$daemonPid process_AEGIS_DAEMON_IFACE=$processPin machine_AEGIS_DAEMON_IFACE=$machinePin"
$selectorsDisjoint = (-not [string]::IsNullOrWhiteSpace($machinePin)) -and (-not [string]::IsNullOrWhiteSpace($noseMachinePin)) -and ($machinePin -ne $noseMachinePin) -and (-not $machinePin.ToLowerInvariant().Contains($noseMachinePin.ToLowerInvariant())) -and (-not $noseMachinePin.ToLowerInvariant().Contains($machinePin.ToLowerInvariant()))
Check 'nose_process_pin_matches' (($nosePid -gt 0) -and ($noseProcessPin -eq $noseMachinePin) -and (-not [string]::IsNullOrWhiteSpace($noseProcessPin))) "nose_pid=$nosePid process_AEGIS_NOSE_IFACE=$noseProcessPin machine_AEGIS_NOSE_IFACE=$noseMachinePin"
Check 'direct_npcap_selectors_disjoint' $selectorsDisjoint "daemon_selector=$machinePin nose_selector=$noseMachinePin"

$arp = @(arp.exe -a -N $ExpectedNidsIp 2>$null)
$kaliSeen = ($arp -match [regex]::Escape($ExpectedKaliIp)).Count -gt 0
$victimSeen = ($arp -match [regex]::Escape($ExpectedVictimIp)).Count -gt 0
Check 'kali_neighbor_present' $kaliSeen "arp_interface=$ExpectedNidsIp kali=$ExpectedKaliIp"
Check 'victim_neighbor_present' $victimSeen "arp_interface=$ExpectedNidsIp victim=$ExpectedVictimIp"

$record = [ordered]@{
    proof = 'rb021_current_source_preflight'
    result = if ($failures.Count -eq 0) { 'RB021_PREFLIGHT_PASS' } else { 'RB021_PREFLIGHT_BLOCKED' }
    evidence_level = 'E1'
    records_head = $gitHead
    build_source_commit = $buildSource
    build_runtime = [ordered]@{ path = $BuildRuntimePath; sha256 = $buildHash }
    installed_runtime = [ordered]@{ path = $InstalledRuntimePath; sha256 = $installedHash }
    topology = [ordered]@{ kali = $ExpectedKaliIp; victim = $ExpectedVictimIp; nids = $ExpectedNidsIp; machine_pin = $machinePin; daemon_pid = $daemonPid; process_pin = $processPin; nose_machine_pin = $noseMachinePin; nose_pid = $nosePid; nose_process_pin = $noseProcessPin }
    checks = $checks
    failures = @($failures)
    host_effect_confirmed = $false
    prevention_gate = 'closed'
    note = 'Read-only gate. It does not start VMs, restart services, send canaries, install filters, or claim E5.'
}
$record | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -Path $recordPath
$record | ConvertTo-Json -Depth 8
if ($failures.Count -gt 0) {
    Write-Warning ('RB021_PREFLIGHT_BLOCKED: ' + ($failures -join '; '))
    exit 2
}
exit 0
