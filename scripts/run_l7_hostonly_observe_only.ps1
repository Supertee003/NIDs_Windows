[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ExpectedKaliIp,
    [int]$ListenPort = 49153,
    [int]$WaitSeconds = 30,
    [string]$ProofOutput = ''
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
if (-not $ProofOutput) { $ProofOutput = Join-Path $repo ("analysis\l7-hostonly-" + (Get-Date -Format 'yyyyMMdd_HHmmss')) }
New-Item -ItemType Directory -Force -Path $ProofOutput | Out-Null

function Invoke-AegisJson([string[]]$CliArgs) {
    $raw = & python tools\aegisctl.py @CliArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw "aegisctl failed ($LASTEXITCODE): $($raw -join [Environment]::NewLine)" }
    return (($raw -join [Environment]::NewLine).Trim() | ConvertFrom-Json)
}
function Get-Number($Object, [string]$Name) {
    $value = $Object.$Name
    if ($null -eq $value) { return [int64]0 }
    return [int64]$value
}

Write-Host '[1/6] Checking healthy runtime and Nose readiness'
$healthBefore = Invoke-AegisJson @('health', '--json')
if ($healthBefore.runtime_state -ne 'RUNNING' -or $healthBefore.degraded -ne $false) { throw 'FAIL_CLOSED: runtime is not healthy' }
if ($healthBefore.workers.nose_ready -ne $true) { throw 'FAIL_CLOSED: nose_ready is not true' }
$before = Invoke-AegisJson @('metrics')
$beforeForensic = Invoke-AegisJson @('forensics', 'verify', '--json')
if ($beforeForensic.verified -ne $true) { throw 'FAIL_CLOSED: forensic chain invalid before L7 probe' }

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $ListenPort)
$listener.Start()
try {
    @(
        'AEGIS L7 host-only benign payload coordinator',
        "expected_kali_ip=$ExpectedKaliIp",
        "listen_port=$ListenPort",
        'probe=normal_http_get',
        'prevention_gate=closed',
        'enforcement=disabled'
    ) | Set-Content -Encoding UTF8 (Join-Path $ProofOutput 'READY.txt')
    Write-Host "[2/6] READY: $ProofOutput\READY.txt"
    Write-Host "Kali should send a normal HTTP GET to $ListenPort within $WaitSeconds seconds."

    $task = $listener.AcceptTcpClientAsync()
    if (-not $task.Wait($WaitSeconds * 1000)) { throw 'FAIL_CLOSED: Kali L7 probe timeout' }
    $client = $task.Result
    $remote = [System.Net.IPEndPoint]$client.Client.RemoteEndPoint
    if ($remote.Address.ToString() -ne $ExpectedKaliIp) { throw "FAIL_CLOSED: unexpected source IP $($remote.Address)" }
    $stream = $client.GetStream()
    $buffer = New-Object byte[] 16384
    $read = $stream.Read($buffer, 0, $buffer.Length)
    $payload = [Text.Encoding]::ASCII.GetString($buffer, 0, $read)
    $payload | Set-Content -Encoding UTF8 (Join-Path $ProofOutput 'payload.txt')
    $response = "HTTP/1.1 200 OK`r`nContent-Length: 27`r`nContent-Type: text/plain`r`nConnection: close`r`n`r`nAEGIS benign observe-only OK`n"
    $responseBytes = [Text.Encoding]::ASCII.GetBytes($response)
    $stream.Write($responseBytes, 0, $responseBytes.Length)
    $stream.Close(); $client.Close()
    Write-Host "[3/6] Accepted HTTP payload from $($remote.Address):$($remote.Port), bytes=$read"

    Start-Sleep -Seconds 2
    $healthAfter = Invoke-AegisJson @('health', '--json')
    $after = Invoke-AegisJson @('metrics')
    $afterForensic = Invoke-AegisJson @('forensics', 'verify', '--json')
    $eventDelta = (Get-Number $after 'events_processed') - (Get-Number $before 'events_processed')
    $forensicDelta = (Get-Number $after 'forensic_records') - (Get-Number $before 'forensic_records')
    $blockDelta = (Get-Number $after 'blocks') - (Get-Number $before 'blocks')
    $errorDelta = (Get-Number $after 'errors') - (Get-Number $before 'errors')
    $noseReadDelta = (Get-Number $healthAfter.data_plane 'nose_frames_read') - (Get-Number $healthBefore.data_plane 'nose_frames_read')
    $noseSubmitDelta = (Get-Number $healthAfter.data_plane 'nose_frames_submitted') - (Get-Number $healthBefore.data_plane 'nose_frames_submitted')

    $noseCaptured = ($noseReadDelta -gt 0 -and $noseSubmitDelta -gt 0)
    $result = [ordered]@{
        proof = 'l7_hostonly_benign_payload_observe_only'
        passed = ($read -gt 0 -and $payload -match '^GET\s' -and $noseCaptured -and $eventDelta -gt 0 -and $forensicDelta -gt 0 -and $afterForensic.verified -eq $true -and $blockDelta -eq 0 -and $errorDelta -eq 0)
        expected_source_ip = $ExpectedKaliIp
        listen_port = $ListenPort
        payload_bytes_received = $read
        payload_http_request = ($payload -match '^GET\s')
        deltas = [ordered]@{
            events_processed = $eventDelta
            forensic_records = $forensicDelta
            nose_frames_read = $noseReadDelta
            nose_frames_submitted = $noseSubmitDelta
            blocks = $blockDelta
            errors = $errorDelta
        }
        forensic_verified = $afterForensic.verified
        host_effect = 'none'
        prevention_gate = 'closed'
        wfp_block_called = $false
        pep_called = $false
        rule_match_status = 'not_asserted_by_this_runner'
        payload_sensor_status = if ($noseCaptured) { 'npcap_go_nose_attribution_observed' } else { 'transport_payload_received_but_npcap_go_nose_attribution_not_observed' }
    }
    $result | ConvertTo-Json -Depth 8
    if (-not $result.passed) { exit 2 }
} finally { $listener.Stop() }
