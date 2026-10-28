# ACQ-ARB E5 proof: verify kernel fallback and Nose handback on the live host.
# Observe-only. Does not deploy binaries, open the prevention gate, or send
# synthetic traffic. Nose is started with -capture, matching aegis_open.py.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo
$evDir = Join-Path (Join-Path $repo 'admin-evidence') 'e5-host-proof-20261026'
New-Item -ItemType Directory -Force -Path $evDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$jsonPath = Join-Path $evDir "e5c-arbiter-verified-$stamp.json"
$transcriptPath = Join-Path $evDir "e5c-arbiter-verified-$stamp.log"
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
        kernel_owned = $queue.wfp.kernel_owned
        shadow_rows = [uint64]$queue.wfp.shadow_rows
        wfp_rows = [uint64]$queue.wfp.rows
        wfp_dropped = if ($wfpSource) { [uint64]$wfpSource.dropped } else { 0 }
        nose_connected = [bool]$health.data_plane.nose_connected
        nose_frames_read = [uint64]$health.data_plane.nose_frames_read
        nose_frames_submitted = [uint64]$health.data_plane.nose_frames_submitted
    }
}

$result = [ordered]@{
    started_at = [DateTime]::Now.ToString('o')
    service_before = (Get-Service AegisNids).Status.ToString()
    takeover_observed = $false
    handback_observed = $false
    nose_frames_advanced = $false
    shadow_rows_advanced = $false
    prevention_gate_before = $null
    prevention_gate_after = $null
    snapshots = @()
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this observe-only host proof from an elevated PowerShell; the current Nose process cannot be stopped by this token.'
    }
    if ($result.service_before -ne 'Running') { throw 'AegisNids must already be running.' }
    $enforceBefore = Invoke-JsonCommand @('tools/aegisctl.py', 'enforce', 'status')
    $result.prevention_gate_before = $enforceBefore.prevention_gate
    if ($enforceBefore.prevention_gate -ne 'closed' -or $enforceBefore.host_effect_capable) {
        throw 'Refusing proof unless prevention gate is closed and host_effect_capable is false.'
    }
    if (-not (Test-Path -LiteralPath $nosePath -PathType Leaf)) { throw "Nose binary missing: $nosePath" }
    $result.nose_sha256 = (Get-FileHash -LiteralPath $nosePath -Algorithm SHA256).Hash.ToUpperInvariant()
    $existingNose = @(Get-Process -Name 'aegis-nose' -ErrorAction SilentlyContinue)
    if ($existingNose.Count -ne 1) { throw "Expected exactly one Nose process before proof; found $($existingNose.Count)." }

    $before = Get-Snapshot
    $result.snapshots += $before
    if ($before.mode -ne 'npcap_primary' -or -not $before.nose_connected) {
        throw 'Proof requires a flowing npcap_primary baseline.'
    }

    Write-Host "baseline mode=$($before.mode) nose_frames_read=$($before.nose_frames_read) shadow_rows=$($before.shadow_rows)"
    Stop-Process -Id $existingNose[0].Id -Force

    $deadline = (Get-Date).AddSeconds(45)
    do {
        Start-Sleep -Seconds 3
        $snap = Get-Snapshot
        $result.snapshots += $snap
        if ($snap.mode -eq 'kernel_fallback' -and $snap.kernel_owned) {
            $result.takeover_observed = $true
            break
        }
    } while ((Get-Date) -lt $deadline)
    if (-not $result.takeover_observed) { throw 'Kernel fallback was not observed within 45 seconds.' }
    Write-Host 'takeover observed; restarting Nose using the capture-mode command line'

    $noseArgs = @('-capture')
    $iface = ($env:AEGIS_NOSE_IFACE, $env:AEGIS_CAPTURE_IFACE | Where-Object { $_ } | Select-Object -First 1)
    if ($iface) { $noseArgs += @('-iface', $iface) }
    $startedNose = Start-Process -FilePath $nosePath -ArgumentList $noseArgs -WindowStyle Hidden -PassThru
    $result.nose_pid = $startedNose.Id

    $deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Seconds 3
        $snap = Get-Snapshot
        $result.snapshots += $snap
        if ($snap.mode -eq 'npcap_primary' -and $snap.nose_connected) {
            $result.handback_observed = $true
            if ($snap.nose_frames_read -gt $before.nose_frames_read -and
                $snap.nose_frames_submitted -gt $before.nose_frames_submitted) {
                $result.nose_frames_advanced = $true
            }
            if ($snap.shadow_rows -gt $before.shadow_rows) { $result.shadow_rows_advanced = $true }
            if ($result.nose_frames_advanced -and $result.shadow_rows_advanced) { break }
        }
    } while ((Get-Date) -lt $deadline)

    $enforceAfter = Invoke-JsonCommand @('tools/aegisctl.py', 'enforce', 'status')
    $result.prevention_gate_after = $enforceAfter.prevention_gate
    $result.host_effect_capable_after = $enforceAfter.host_effect_capable
    $result.gate = ($result.takeover_observed -and $result.handback_observed -and
        $result.nose_frames_advanced -and $result.shadow_rows_advanced -and
        $result.prevention_gate_after -eq 'closed' -and -not $result.host_effect_capable_after)
    $result.finished_at = [DateTime]::Now.ToString('o')
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    Write-Host "takeover=$($result.takeover_observed) handback=$($result.handback_observed) nose_frames_advanced=$($result.nose_frames_advanced) shadow_rows_advanced=$($result.shadow_rows_advanced) gate=$($result.gate)"
} catch {
    $result.error = $_.Exception.Message
    $result.finished_at = [DateTime]::Now.ToString('o')
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    Write-Warning $_
} finally {
    Stop-Transcript
}

if (-not $result.gate) { exit 1 }
