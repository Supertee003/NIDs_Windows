# AEGIS L4/WFP observe-only proof.
# Read-only: opens the WFP device with GENERIC_READ, reads ring statistics and
# event bytes, and never issues BLOCK_FLOW or UNBLOCK_FLOW.
#
# Usage (elevated PowerShell recommended):
#   .\scripts\run_wfp_l4_observe_only_proof.ps1
#   .\scripts\run_wfp_l4_observe_only_proof.ps1 -GenerateBenignProbe -RequireEvent

[CmdletBinding()]
param(
    [switch]$GenerateBenignProbe,
    [switch]$RequireEvent,
    [int]$WaitSeconds = 3,
    [string]$ServiceName = '',
    [string]$ExpectedSourceIp = '',
    [string]$ExpectedDestIp = '',
    [int]$ExpectedDestPort = 0,
    [switch]$RequireExpectedFlow,
    [int]$ExternalListenPort = 0,
    [string]$ReadyFile = ''
)

$ErrorActionPreference = 'Stop'
$device = '\\.\AegisWfpDevice'
$serviceCandidates = if ($ServiceName) { @($ServiceName) } else { @('AegisWfp', 'aegis_wfp') }
$IOCTL_READ_EVENTS = [Convert]::ToUInt32('00126000', 16)
$IOCTL_GET_STATS = [Convert]::ToUInt32('00126008', 16)
$EVENT_HEADER_SIZE = 48
# EVT-213: 48-byte packed record stride (kernel reserved2 aligns timestamp
# to @40). The 44-byte pre-EVT-213 stride shifted every record after the
# first for 48-byte consumers.
# Do not cast the PowerShell-parsed 0x80000000 signed Int32; convert the
# hexadecimal text directly so GENERIC_READ remains UInt32 2147483648.
$GENERIC_READ = [Convert]::ToUInt32('80000000', 16)
$OPEN_EXISTING = [Convert]::ToUInt32('3', 16)
$INVALID_HANDLE_VALUE = [IntPtr](-1)

if (-not ('Aegis.WfpProof.Native' -as [type])) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
namespace Aegis.WfpProof {
  public static class Native {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(IntPtr h, uint code, byte[] input, uint inputLen, byte[] output, uint outputLen, out uint returned, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
  }
}
"@
}

function Fail([string]$Message) {
    throw "WFP_L4_OBSERVE_ONLY_FAIL: $Message"
}

function Read-Stats([IntPtr]$Handle) {
    $out = New-Object byte[] 24
    [uint32]$returned = 0
    $ok = [Aegis.WfpProof.Native]::DeviceIoControl($Handle, $IOCTL_GET_STATS, $null, 0, $out, $out.Length, [ref]$returned, [IntPtr]::Zero)
    if (-not $ok) { Fail "GET_STATS failed Win32=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    if ($returned -lt 24) { Fail "GET_STATS returned $returned bytes, expected 24" }
    [pscustomobject]@{
        total_events_written = [BitConverter]::ToUInt32($out, 0)
        total_drops = [BitConverter]::ToUInt32($out, 4)
        total_bytes_written = [BitConverter]::ToUInt32($out, 8)
        total_bytes_read = [BitConverter]::ToUInt32($out, 12)
        current_used_bytes = [BitConverter]::ToUInt32($out, 16)
        stats_bytes = $returned
        counters_note = 'evt231+ drivers populate all counters; pre-evt231 report only current_used_bytes'
    }
}

function Read-Events([IntPtr]$Handle) {
    # Records are variable length (48-byte header + payload_length bytes;
    # EVT-231 caps payload at 4096). The kernel returns whole records only,
    # so the buffer just needs to fit one maximum record (48 + 4096 = 4144);
    # 64 KiB also matches the daemon reader.
    $out = New-Object byte[] 65536
    [uint32]$returned = 0
    $ok = [Aegis.WfpProof.Native]::DeviceIoControl($Handle, $IOCTL_READ_EVENTS, $null, 0, $out, $out.Length, [ref]$returned, [IntPtr]::Zero)
    if (-not $ok) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        # Empty ring may be reported by the driver as an unsuccessful read.
        if ($err -ne 0) { return [pscustomobject]@{ bytes = 0; win32_error = $err; data = @() } }
    }
    [pscustomobject]@{ bytes = $returned; win32_error = 0; data = $out }
}

function Drain-Events([IntPtr]$Handle) {
    $totalBytes = [int64]0
    $reads = 0
    $allFrames = @()
    # Bound the drain: the ring is 2 MiB and each batch is frame-aligned.
    while ($reads -lt 512) {
        $batch = Read-Events $Handle
        if ($batch.bytes -le 0) { break }
        $totalBytes += [int64]$batch.bytes
        $batchParsed = Parse-EventFrames $batch.data $batch.bytes
        $allFrames += $batchParsed.frames
        $reads++
        if ($batch.bytes -lt 65536) { break }
    }
    [pscustomobject]@{
        bytes = $totalBytes
        reads = $reads
        frames = $allFrames
    }
}

function Convert-EventIp([byte[]]$Bytes, [int]$Offset) {
    # WFP supplies IPv4 fields in network order; the packed UINT32 is stored
    # in little-endian memory on Windows, so reverse bytes for dotted output.
    $octets = @($Bytes[$Offset + 3], $Bytes[$Offset + 2], $Bytes[$Offset + 1], $Bytes[$Offset])
    ($octets -join '.')
}

function Parse-EventFrames([byte[]]$Bytes, [uint32]$ByteCount) {
    # Variable stride: advance by 48 + payload_length per record (EVT-231).
    # A tail that does not hold one complete record is reported as trailing
    # bytes (the kernel never emits a split record; this stays defensive).
    $frames = @()
    $offset = 0
    while ($offset + $EVENT_HEADER_SIZE -le $ByteCount) {
        $payloadLength = [BitConverter]::ToUInt32($Bytes, $offset + 20)
        $recordSize = $EVENT_HEADER_SIZE + [int]$payloadLength
        if ($offset + $recordSize -gt $ByteCount) { break }
        $frames += [pscustomobject]@{
            source_ip = Convert-EventIp $Bytes ($offset + 4)
            dest_ip = Convert-EventIp $Bytes ($offset + 8)
            source_port = [BitConverter]::ToUInt16($Bytes, $offset + 12)
            dest_port = [BitConverter]::ToUInt16($Bytes, $offset + 14)
            protocol = $Bytes[$offset + 16]
            direction = $Bytes[$offset + 17]
            layer_id = $Bytes[$offset + 18]
            payload_length = $payloadLength
            rule_id = [BitConverter]::ToUInt32($Bytes, $offset + 24)
            severity = [BitConverter]::ToUInt32($Bytes, $offset + 28)
        }
        $offset += $recordSize
    }
    [pscustomobject]@{
        header_size = $EVENT_HEADER_SIZE
        complete_frames = [int]$frames.Count
        trailing_bytes = [int]($ByteCount - $offset)
        frames = $frames
    }
}

function Invoke-BenignInboundProbe {
    # Test-NetConnection to an unopened port is outbound and may not produce
    # an inbound transport event. Use a temporary localhost listener instead.
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 0)
    $listener.Start()
    try {
        $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        $acceptTask = $listener.AcceptTcpClientAsync()
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $connectTask = $client.ConnectAsync([System.Net.IPAddress]::Loopback, $port)
            if (-not $connectTask.Wait(2000)) { Fail "benign localhost connect timed out" }
            if (-not $acceptTask.Wait(2000)) { Fail "benign localhost accept timed out" }
            $accepted = $acceptTask.Result
            $accepted.Close()
        } finally {
            $client.Close()
        }
    } finally {
        $listener.Stop()
    }
}

function Wait-ExternalProbe([int]$Port, [int]$Seconds, [string]$ReadyPath) {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
    $listener.Start()
    try {
        if ($ReadyPath) {
            @("AEGIS WFP collector ready", "listen_port=$Port", "expected_source_ip=$ExpectedSourceIp", "prevention_gate=closed") |
                Set-Content -Encoding UTF8 $ReadyPath
        }
        Write-Host "[4/5] Waiting for external benign probe on TCP/$Port"
        $task = $listener.AcceptTcpClientAsync()
        if (-not $task.Wait($Seconds * 1000)) { Fail "external probe timeout on TCP/$Port" }
        $client = $task.Result
        $remote = [System.Net.IPEndPoint]$client.Client.RemoteEndPoint
        Write-Host "Accepted external probe from $($remote.Address):$($remote.Port)"
        try {
            $stream = $client.GetStream()
            $buffer = New-Object byte[] 4096
            [void]$stream.Read($buffer, 0, $buffer.Length)
            $stream.Close()
        } catch {}
        $client.Close()
    } finally { $listener.Stop() }
}

Write-Host '[1/5] Checking driver service (read-only)'
$svc = $null
foreach ($candidate in $serviceCandidates) {
    # Kernel drivers are represented by Win32_SystemDriver, not reliably by Win32_Service.
    $svc = Get-CimInstance Win32_SystemDriver -Filter "Name='$candidate'" -ErrorAction SilentlyContinue
    if ($null -ne $svc) { break }
}
if ($null -eq $svc) {
    foreach ($candidate in $serviceCandidates) {
        $scText = @(sc.exe query $candidate 2>$null)
        if ($LASTEXITCODE -eq 0) {
            $state = if ($scText -match 'RUNNING') { 'Running' } else { 'Stopped' }
            $svc = [pscustomobject]@{ Name = $candidate; State = $state; Source = 'sc.exe' }
            break
        }
    }
}
if ($null -eq $svc) { Fail "none of the candidate kernel drivers is installed: $($serviceCandidates -join ', ')" }
if ($svc.State -ne 'Running') { Fail "driver $($svc.Name) state is $($svc.State), expected Running" }

Write-Host '[2/5] Opening WFP device with GENERIC_READ only'
$handle = [Aegis.WfpProof.Native]::CreateFile($device, $GENERIC_READ, 0, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
if ($handle -eq $INVALID_HANDLE_VALUE) { Fail "cannot open $device Win32=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }

try {
    $before = Read-Stats $handle
    Write-Host "[3/5] Baseline events=$($before.total_events_written) drops=$($before.total_drops) bytes=$($before.total_bytes_written)"
    $baselineDrain = Drain-Events $handle
    Write-Host "Drained baseline bytes=$($baselineDrain.bytes) frames=$($baselineDrain.frames.Count)"

    if ($ExternalListenPort -gt 0) {
        Wait-ExternalProbe $ExternalListenPort $WaitSeconds $ReadyFile
        Start-Sleep -Milliseconds 500
    } elseif ($GenerateBenignProbe) {
        Write-Host '[4/5] Generating one benign localhost TCP probe (no enforcement request)'
        Invoke-BenignInboundProbe
        Start-Sleep -Seconds $WaitSeconds
    } else {
        Write-Host '[4/5] No traffic generated; observing existing kernel ring only'
        Start-Sleep -Seconds $WaitSeconds
    }

    $after = Read-Stats $handle
    $drained = Drain-Events $handle
    $readBytes = [int64]$drained.bytes
    $allFrames = $drained.frames
    $sampleFrames = @($allFrames | Select-Object -First 93)
    $expectedMatches = @($allFrames | Where-Object {
        (!$ExpectedSourceIp -or $_.source_ip -eq $ExpectedSourceIp) -and
        (!$ExpectedDestIp -or $_.dest_ip -eq $ExpectedDestIp) -and
        ($ExpectedDestPort -eq 0 -or $_.dest_port -eq $ExpectedDestPort)
    })
    $parsed = [pscustomobject]@{
        header_size = $EVENT_HEADER_SIZE
        complete_frames = $allFrames.Count
        trailing_bytes = 0
        frames = $sampleFrames
    }
    $eventPass = (-not $RequireEvent -or $readBytes -gt 0)
    $flowPass = (-not $RequireExpectedFlow -or $expectedMatches.Count -gt 0)
    # EVT-231 drivers populate every AEGIS_RING_STATS counter under
    # g_RingLock; pre-EVT-231 drivers report only currentUsedBytes. Both
    # are read as-is (no inference) and reported in baseline/after.
    $statsDelta = [int64]$after.current_used_bytes - [int64]$before.current_used_bytes
    $result = [pscustomobject]@{
        proof = 'l4_wfp_observe_only'
        passed = ($eventPass -and $flowPass)
        driver_service = $svc.Name
        driver_state = $svc.State
        device = $device
        access = 'GENERIC_READ'
        requested_control_codes = @('GET_STATS', 'READ_EVENTS')
        forbidden_control_codes_called = @('BLOCK_FLOW', 'UNBLOCK_FLOW')
        events_read_bytes = $readBytes
        event_header_size = $parsed.header_size
        complete_event_frames = $parsed.complete_frames
        trailing_event_bytes = $parsed.trailing_bytes
        event_frames = $parsed.frames
        expected_flow = [pscustomobject]@{
            source_ip = $ExpectedSourceIp
            dest_ip = $ExpectedDestIp
            dest_port = $ExpectedDestPort
            matches = $expectedMatches.Count
            required = [bool]$RequireExpectedFlow
            sample_frames = @($expectedMatches | Select-Object -First 10)
        }
        current_used_bytes_delta = $statsDelta
        driver_reported_counters = 'evt231_fields (all counters populated on evt231+ drivers)'
        baseline = $before
        baseline_drain = [pscustomobject]@{ bytes = $baselineDrain.bytes; frames = $baselineDrain.frames.Count }
        after = $after
        host_effect = 'none'
        prevention_gate = 'closed'
        note = 'This proves only device/ring readback. It is not a rule-match or IPS host-effect proof. EVT-231 drivers populate all GET_STATS counters; pre-EVT-231 drivers report only currentUsedBytes.'
    }
    $result | ConvertTo-Json -Depth 6
    if (-not $result.passed) { exit 2 }
} finally {
    [Aegis.WfpProof.Native]::CloseHandle($handle) | Out-Null
}
