# O2 E5 proof: verify an outbound WFP record reaches the authenticated
# forensic read path with direction=1. Observe-only; uses loopback TCP only,
# stops/restarts Nose to make WFP the sole submitted ingress, and never opens
# prevention or changes WFP filters/services.
# Requires elevated PowerShell because the running Nose process is protected.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo
$evDir = Join-Path (Join-Path $repo 'admin-evidence') 'e5-host-proof-20261026'
New-Item -ItemType Directory -Force -Path $evDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$jsonPath = Join-Path $evDir "e5d-o2-direction-$stamp.json"
$transcriptPath = Join-Path $evDir "e5d-o2-direction-$stamp.log"
$nosePath = 'C:\Program Files\AEGIS NIDS\runtime\aegis-nose.exe'
Start-Transcript -Path $transcriptPath -Force

function Invoke-JsonCommand([string[]]$Command) {
    $raw = & python @Command 2>&1 | Out-String
    $start = $raw.IndexOf('{')
    if ($start -lt 0) { throw "No JSON response from: $($Command -join ' ')`n$raw" }
    return ($raw.Substring($start) | ConvertFrom-Json)
}

function Get-Snapshot {
    $queue = Invoke-JsonCommand @('tools/aegisctl.py', 'queue', '--json')
    $health = Invoke-JsonCommand @('tools/aegisctl.py', 'health', '--json')
    $wfpSource = $queue.by_source | Where-Object { $_.name -eq 'capture_wfp' } | Select-Object -First 1
    return [ordered]@{
        at = [DateTime]::Now.ToString('o')
        mode = $queue.wfp.mode
        reason = $queue.wfp.reason
        kernel_owned = [bool]$queue.wfp.kernel_owned
        wfp_rows = [uint64]$queue.wfp.rows
        shadow_rows = [uint64]$queue.wfp.shadow_rows
        wfp_dropped = if ($wfpSource) { [uint64]$wfpSource.dropped } else { 0 }
        nose_connected = [bool]$health.data_plane.nose_connected
        nose_frames_read = [uint64]$health.data_plane.nose_frames_read
        nose_frames_submitted = [uint64]$health.data_plane.nose_frames_submitted
    }
}

$result = [ordered]@{
    started_at = [DateTime]::Now.ToString('o')
    service_before = (Get-Service AegisNids).Status.ToString()
    driver_before = (Get-Service AegisWfp).Status.ToString()
    takeover_observed = $false
    marker_received_by_loopback_server = $false
    forensic_match = $false
    outbound_direction_observed = $false
    handback_observed = $false
    prevention_gate_before = $null
    prevention_gate_after = $null
    snapshots = @()
}
$noseStopped = $false
$noseStarted = $false
$existingNose = @()
$startedNose = $null

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run elevated; the running Nose process cannot be stopped by this token.'
    }
    if ($result.service_before -ne 'Running' -or $result.driver_before -ne 'Running') {
        throw 'AegisNids and AegisWfp must already be RUNNING.'
    }
    $enforceBefore = Invoke-JsonCommand @('tools/aegisctl.py', 'enforce', 'status')
    $result.prevention_gate_before = $enforceBefore.prevention_gate
    if ($enforceBefore.prevention_gate -ne 'closed' -or $enforceBefore.host_effect_capable) {
        throw 'Refusing proof unless prevention_gate=closed and host_effect_capable=false.'
    }
    if (-not (Test-Path -LiteralPath $nosePath -PathType Leaf)) { throw "Nose binary missing: $nosePath" }
    $result.nose_sha256 = (Get-FileHash -LiteralPath $nosePath -Algorithm SHA256).Hash.ToUpperInvariant()
    $existingNose = @(Get-Process -Name 'aegis-nose' -ErrorAction SilentlyContinue)
    if ($existingNose.Count -ne 1) { throw "Expected one Nose process; found $($existingNose.Count)." }

    $before = Get-Snapshot
    $result.snapshots += $before
    if ($before.mode -ne 'npcap_primary' -or -not $before.nose_connected) {
        throw 'Require a flowing npcap_primary baseline before takeover.'
    }

    $enforceSource = (Invoke-JsonCommand @('tools/aegisctl.py', 'forensics', 'verify'))
    if ($enforceSource.verified -ne $true) { throw 'Forensic hash chain is not verified before the probe.' }
    Write-Host "baseline mode=$($before.mode) wfp_rows=$($before.wfp_rows) nose_frames=$($before.nose_frames_submitted)"

    Stop-Process -Id $existingNose[0].Id -Force
    $noseStopped = $true
    $deadline = (Get-Date).AddSeconds(45)
    do {
        Start-Sleep -Seconds 2
        $snap = Get-Snapshot
        $result.snapshots += $snap
        if ($snap.mode -eq 'kernel_fallback' -and $snap.kernel_owned) {
            $result.takeover_observed = $true
            break
        }
    } while ((Get-Date) -lt $deadline)
    if (-not $result.takeover_observed) { throw 'Kernel fallback was not observed within 45 seconds.' }

    # Generate a unique one-way TCP payload on loopback. No external host,
    # policy edit, filter mutation, or prevention request is involved.
    $marker = "AEGIS-O2-DIRECTION-$([Guid]::NewGuid().ToString('N'))"
    $result.marker = $marker
    $markerBytes = [Text.Encoding]::ASCII.GetBytes($marker)
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $result.loopback_port = $port
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $client.Connect([Net.IPAddress]::Loopback, $port)
            $server = $listener.AcceptTcpClient()
            try {
                $clientStream = $client.GetStream()
                $clientStream.Write($markerBytes, 0, $markerBytes.Length)
                $clientStream.Flush()
                $serverStream = $server.GetStream()
                $received = New-Object byte[] $markerBytes.Length
                $read = 0
                while ($read -lt $received.Length) {
                    $chunk = $serverStream.Read($received, $read, $received.Length - $read)
                    if ($chunk -le 0) { break }
                    $read += $chunk
                }
                $result.marker_received_by_loopback_server = ($read -eq $markerBytes.Length -and
                    [Text.Encoding]::ASCII.GetString($received, 0, $read) -ceq $marker)
            } finally { $server.Dispose() }
        } finally { $client.Dispose() }
    } finally { $listener.Stop() }
    if (-not $result.marker_received_by_loopback_server) { throw 'Loopback server did not receive the exact marker.' }

    $deadline = (Get-Date).AddSeconds(20)
    do {
        $matches = Invoke-JsonCommand @('tools/aegisctl.py', 'forensics', 'list', '--json', '--limit', '1000', '--source', '1', '--payload-prefix', $marker)
        $record = $matches.records | Where-Object { $_.source_name -eq 'wfp_sensor' -and $_.direction -eq 1 } | Select-Object -First 1
        if ($record) {
            $result.forensic_match = $true
            $result.outbound_direction_observed = $true
            $result.forensic_record = $record
            $result.forensic_integrity = $matches.integrity
            $result.forensic_verified = $matches.verified
            break
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    if (-not $result.outbound_direction_observed) {
        throw 'No authenticated WFP forensic record with matching payload prefix and direction=1 was returned.'
    }

    $afterTraffic = Get-Snapshot
    $result.snapshots += $afterTraffic
    $result.wfp_rows_advanced = ($afterTraffic.wfp_rows -gt $before.wfp_rows)
} catch {
    $result.error = $_.Exception.Message
} finally {
    if ($noseStopped) {
        try {
            $runningNose = @(Get-Process -Name 'aegis-nose' -ErrorAction SilentlyContinue)
            if ($runningNose.Count -eq 0 -and (Test-Path -LiteralPath $nosePath)) {
                $noseArgs = @('-capture')
                $iface = ($env:AEGIS_NOSE_IFACE, $env:AEGIS_CAPTURE_IFACE | Where-Object { $_ } | Select-Object -First 1)
                if ($iface) { $noseArgs += @('-iface', $iface) }
                $startedNose = Start-Process -FilePath $nosePath -ArgumentList $noseArgs -WindowStyle Hidden -PassThru
                $noseStarted = $true
                $result.nose_pid = $startedNose.Id
            } elseif ($runningNose.Count -eq 1) {
                $noseStarted = $true
            } else {
                $result.nose_restart_error = "Expected zero or one running Nose process; found $($runningNose.Count)."
            }
        } catch { $result.nose_restart_error = $_.Exception.Message }
    }
    if ($noseStarted) {
        $deadline = (Get-Date).AddSeconds(60)
        do {
            Start-Sleep -Seconds 2
            try {
                $snap = Get-Snapshot
                $result.snapshots += $snap
                if ($snap.mode -eq 'npcap_primary' -and $snap.nose_connected) {
                    $result.handback_observed = $true
                    break
                }
            } catch { }
        } while ((Get-Date) -lt $deadline)
    }
    try {
        $enforceAfter = Invoke-JsonCommand @('tools/aegisctl.py', 'enforce', 'status')
        $result.prevention_gate_after = $enforceAfter.prevention_gate
        $result.host_effect_capable_after = $enforceAfter.host_effect_capable
    } catch { $result.final_status_error = $_.Exception.Message }
    try {
        $result.forensic_chain_after = Invoke-JsonCommand @('tools/aegisctl.py', 'forensics', 'verify')
    } catch { $result.forensic_chain_error = $_.Exception.Message }
    $result.finished_at = [DateTime]::Now.ToString('o')
    $result.gate = ($result.takeover_observed -and $result.marker_received_by_loopback_server -and
        $result.outbound_direction_observed -and $result.wfp_rows_advanced -and
        $result.handback_observed -and $result.prevention_gate_before -eq 'closed' -and
        $result.prevention_gate_after -eq 'closed' -and -not $result.host_effect_capable_after -and
        $result.forensic_chain_after.verified -eq $true)
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    Write-Host "takeover=$($result.takeover_observed) marker=$($result.marker_received_by_loopback_server) outbound_direction=$($result.outbound_direction_observed) wfp_rows_advanced=$($result.wfp_rows_advanced) handback=$($result.handback_observed) gate=$($result.gate)"
    Stop-Transcript
}

if (-not $result.gate) { exit 1 }
