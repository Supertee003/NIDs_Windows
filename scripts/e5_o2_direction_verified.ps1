# O2 E5 proof: verify an outbound WFP record reaches the authenticated
# forensic read path with direction=1. Observe-only; uses an operator-controlled remote TCP sink,
# stops/restarts Nose to make WFP the sole submitted ingress, and never opens
# prevention or changes WFP filters/services.
# Requires an operator-controlled remote TCP listener accepting the marker.
# Requires elevated PowerShell because the running Nose process is protected.
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RemoteAddress,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int]$RemotePort
)
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
$daemonPath = 'C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe'
$expectedDaemonHash = 'E19370F598507FBC9A1194EA8182059B319DFAF76DFF4D3DE34814C57386B407'
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
    marker_sent_to_remote = $false
    forensic_match = $false
    outbound_direction_observed = $false
    forensic_query_records_matched = 0
    forensic_query_records_returned = 0
    forensic_readiness_attempts = 0
    diagnostic_marker_records = @()
    forensic_integrity_during_probe = $null
    handback_observed = $false
    nose_frames_advanced_after_handback = $false
    nose_frames_submitted_advanced_after_handback = $false
    remote_address = $RemoteAddress
    remote_port = $RemotePort
    prevention_gate_before = $null
    prevention_gate_after = $null
    snapshots = @()
}
$noseStopped = $false
$noseStarted = $false
$existingNose = @()
$startedNose = $null
$baseline = $null

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
    $result.daemon_sha256 = (Get-FileHash -LiteralPath $daemonPath -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($result.daemon_sha256 -ne $expectedDaemonHash) {
        throw "Installed daemon hash $($result.daemon_sha256) does not match the E5-pinned candidate $expectedDaemonHash."
    }
    $featureProbe = $null
    $probeRecords = @()
    $lastFeatureProbeError = 'No forensic records returned yet.'
    $readinessDeadline = (Get-Date).AddSeconds(45)
    do {
        $result.forensic_readiness_attempts++
        $candidateFeatureProbe = $null
        try {
            $candidateFeatureProbe = Invoke-JsonCommand @('tools/aegisctl.py', 'forensics', 'list', '--json', '--limit', '1')
        } catch {
            $lastFeatureProbeError = $_.Exception.Message
        }
        if ($candidateFeatureProbe) {
            $candidateRecords = @($candidateFeatureProbe.records)
            if ($candidateRecords.Count -gt 0) {
                if (-not $candidateRecords[0].PSObject.Properties['direction']) {
                    throw 'The live daemon predates O2 direction metadata; deploy the current zig-out/bin/aegis_nids.exe before running this E5 proof.'
                }
                $featureProbe = $candidateFeatureProbe
                $probeRecords = $candidateRecords
                break
            }
            $lastFeatureProbeError = 'Control responded, but the forensic ring has no retained records yet.'
        }
        if ((Get-Date) -lt $readinessDeadline) { Start-Sleep -Seconds 1 }
    } while ((Get-Date) -lt $readinessDeadline)
    if (-not $featureProbe) {
        throw "Cannot validate runtime feature support after 45 seconds: $lastFeatureProbeError"
    }
    if (-not (Test-Path -LiteralPath $nosePath -PathType Leaf)) { throw "Nose binary missing: $nosePath" }
    $result.nose_sha256 = (Get-FileHash -LiteralPath $nosePath -Algorithm SHA256).Hash.ToUpperInvariant()
    $existingNose = @(Get-Process -Name 'aegis-nose' -ErrorAction SilentlyContinue)
    if ($existingNose.Count -ne 1) { throw "Expected one Nose process; found $($existingNose.Count)." }

    $baseline = Get-Snapshot
    $result.snapshots += $baseline
    if ($baseline.mode -ne 'npcap_primary' -or -not $baseline.nose_connected) {
        throw 'Require a flowing npcap_primary baseline before takeover.'
    }

    $enforceSource = (Invoke-JsonCommand @('tools/aegisctl.py', 'forensics', 'verify'))
    if ($enforceSource.verified -ne $true) { throw 'Forensic hash chain is not verified before the probe.' }
    Write-Host "baseline mode=$($baseline.mode) wfp_rows=$($baseline.wfp_rows) nose_frames=$($baseline.nose_frames_submitted)"

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

    # Send a unique one-way TCP payload to an operator-controlled remote
    # listener. Loopback is excluded because its server-side inbound callback
    # can record the same payload as direction=0.
    $marker = "AEGIS-O2-DIRECTION-$([Guid]::NewGuid().ToString('N'))"
    $result.marker = $marker
    $markerBytes = [Text.Encoding]::ASCII.GetBytes($marker)
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $client.Connect($RemoteAddress, $RemotePort)
        $stream = $client.GetStream()
        $stream.Write($markerBytes, 0, $markerBytes.Length)
        $stream.Flush()
        $result.marker_sent_to_remote = $true
    } finally { $client.Dispose() }
    if (-not $result.marker_sent_to_remote) { throw 'Remote TCP sink did not accept the marker write.' }

    # Capture transport activity before querying forensic attribution so a
    # missing record still leaves evidence of whether the WFP ring advanced.
    $afterTraffic = Get-Snapshot
    $result.snapshots += $afterTraffic
    $result.wfp_rows_advanced = ($afterTraffic.wfp_rows -gt $baseline.wfp_rows)

    $deadline = (Get-Date).AddSeconds(20)
    do {
        # Do not filter by source here: keep marker-matching rows from any
        # source so the proof can distinguish attribution drift from a
        # missing payload/evidence record.
        $matches = Invoke-JsonCommand @('tools/aegisctl.py', 'forensics', 'list', '--json', '--limit', '1000', '--payload-prefix', $marker)
        $result.forensic_query_records_matched = [uint64]$matches.records_matched
        $result.forensic_query_records_returned = [uint64]$matches.records_returned
        $result.forensic_integrity_during_probe = $matches.integrity
        $result.diagnostic_marker_records = @($matches.records)
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
        $observed = if ($result.diagnostic_marker_records.Count -gt 0) {
            ($result.diagnostic_marker_records | ForEach-Object { "source=$($_.source_name) direction=$($_.direction) seq=$($_.record_seq)" }) -join '; '
        } else { 'no exact payload-prefix record from any source' }
        throw "No authenticated WFP forensic record with matching payload prefix and direction=1 was returned; matched=$($result.forensic_query_records_matched) records=[$observed]."
    }
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
                if ($baseline) {
                    $result.nose_frames_advanced_after_handback = $snap.nose_frames_read -gt $baseline.nose_frames_read
                    $result.nose_frames_submitted_advanced_after_handback = $snap.nose_frames_submitted -gt $baseline.nose_frames_submitted
                }
                if ($snap.mode -eq 'npcap_primary' -and $snap.nose_connected -and
                    $result.nose_frames_advanced_after_handback -and
                    $result.nose_frames_submitted_advanced_after_handback) {
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
    $result.gate = ($result.takeover_observed -and $result.marker_sent_to_remote -and
        $result.outbound_direction_observed -and $result.wfp_rows_advanced -and
        $result.handback_observed -and $result.nose_frames_advanced_after_handback -and
        $result.nose_frames_submitted_advanced_after_handback -and
        $result.prevention_gate_before -eq 'closed' -and
        $result.prevention_gate_after -eq 'closed' -and -not $result.host_effect_capable_after -and
        $result.forensic_chain_after.verified -eq $true)
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    Write-Host "takeover=$($result.takeover_observed) marker_sent=$($result.marker_sent_to_remote) outbound_direction=$($result.outbound_direction_observed) wfp_rows_advanced=$($result.wfp_rows_advanced) handback=$($result.handback_observed) nose_read_advanced=$($result.nose_frames_advanced_after_handback) nose_submitted_advanced=$($result.nose_frames_submitted_advanced_after_handback) gate=$($result.gate)"
    Stop-Transcript
}

if (-not $result.gate) { exit 1 }
