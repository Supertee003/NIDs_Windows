[CmdletBinding()]
param(
    [int]$WaitSeconds = 14,
    [string]$EvidencePath = (Join-Path $env:TEMP 'AEGIS-native-pipe-proof.json')
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AegisNativePipeFixture {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr CreateNamedPipeW(
        string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances,
        uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut,
        IntPtr lpSecurityAttributes);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);
    public static IntPtr Create(string shortName) {
        return CreateNamedPipeW(
            @"\\.\pipe\" + shortName,
            0x00000003u, // PIPE_ACCESS_DUPLEX
            0x00000000u, // byte pipe, blocking mode
            1u, 4096u, 4096u, 0u, IntPtr.Zero);
    }
    public static void Close(IntPtr handle) {
        if (handle != IntPtr.Zero && handle.ToInt64() != -1) CloseHandle(handle);
    }
}
'@

function Invoke-AegisJson([string[]]$CliArgs) {
    $raw = & python tools\aegisctl.py @CliArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw "aegisctl failed ($LASTEXITCODE): $($raw -join [Environment]::NewLine)" }
    $text = ($raw -join [Environment]::NewLine).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { throw 'aegisctl returned empty output' }
    return $text | ConvertFrom-Json
}

function Get-Number($Object, [string]$Name) {
    $value = $Object.$Name
    if ($null -eq $value) { return [int64]0 }
    return [int64]$value
}

$pipeName = 'MSSE-AEGIS-PROOF-' + ([Guid]::NewGuid().ToString('N'))
$nativePipeHandle = [IntPtr]::Zero
$before = $null
$beforeForensic = $null
$after = $null
$afterForensic = $null
$result = $null

try {
    Write-Host '[1/6] Checking runtime and forensic readiness'
    $health = Invoke-AegisJson @('health', '--json')
    Write-Host "[AEGIS HEALTH] state=$($health.state) degraded=$($health.degraded)"
    if ($health.state -ne 'RUNNING') {
        $healthJson = $health | ConvertTo-Json -Depth 8 -Compress
        throw "FAIL_CLOSED: runtime state is not RUNNING (health=$healthJson). Start the single runtime owner first with: zig build run"
    }
    if ($health.workers.nose_ready -ne $true) { throw 'FAIL_CLOSED: nose_ready is not true' }

    $before = Invoke-AegisJson @('metrics')
    $beforeForensic = Invoke-AegisJson @('forensics', 'verify', '--json')
    if ($beforeForensic.verified -ne $true) { throw 'FAIL_CLOSED: forensic chain invalid before probe' }

    Write-Host "[2/6] Creating temporary native named pipe: $pipeName"
    # Use the same Win32 API family as the sensor. The handle is never
    # connected and carries no payload; it only exposes the benign name to
    # FindFirstFileW(\\.\pipe\*).
    $nativePipeHandle = [AegisNativePipeFixture]::Create($pipeName)
    if ($nativePipeHandle -eq [IntPtr]::Zero -or $nativePipeHandle.ToInt64() -eq -1) {
        throw "CreateNamedPipeW failed: Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    Write-Host "[3/6] Waiting $WaitSeconds second(s) for Thread 5 enumeration"
    Start-Sleep -Seconds $WaitSeconds

    $after = Invoke-AegisJson @('metrics')
    $afterForensic = Invoke-AegisJson @('forensics', 'verify', '--json')
    $sourceOnly = Invoke-AegisJson @('forensics', 'list', '--json', '--source', '5')
    $payloadOnly = Invoke-AegisJson @('forensics', 'list', '--json', '--payload-prefix', $pipeName)
    $exact = Invoke-AegisJson @('forensics', 'list', '--json', '--source', '5', '--payload-prefix', $pipeName)
    $eventDelta = (Get-Number $after 'events_processed') - (Get-Number $before 'events_processed')
    $forensicDelta = (Get-Number $after 'forensic_records') - (Get-Number $before 'forensic_records')
    $blockDelta = (Get-Number $after 'blocks') - (Get-Number $before 'blocks')
    $errorDelta = (Get-Number $after 'errors') - (Get-Number $before 'errors')
    $exactAttribution = ($exact.records -eq 1 -and $null -ne $exact.match -and
        [int64]$exact.match.event_id -gt 0 -and [int64]$exact.match.rule_id -ne 0 -and
        [int]$exact.match.source -eq 5)

    Write-Host '[4/6] Disposing temporary named pipe; no enforcement requested'
    [AegisNativePipeFixture]::Close($nativePipeHandle)
    $nativePipeHandle = [IntPtr]::Zero

    $result = [ordered]@{
        proof = 'native_named_pipe_runtime_observe_only'
        passed = ($eventDelta -gt 0 -and $forensicDelta -gt 0 -and $afterForensic.verified -eq $true -and $exactAttribution -and $blockDelta -eq 0 -and $errorDelta -eq 0)
        pipe_name = $pipeName
        sensor = 'Thread 5 FindFirstFileW(\\.\pipe\*)'
        deltas = [ordered]@{
            events_processed = $eventDelta
            forensic_records = $forensicDelta
            blocks = $blockDelta
            errors = $errorDelta
        }
        forensic_verified = $afterForensic.verified
        exact_attribution = $exactAttribution
        source_only_query = $sourceOnly
        payload_only_query = $payloadOnly
        exact_query = $exact
        exact_record = $exact.match
        host_effect = 'none'
        prevention_gate = 'closed'
        wfp_block_called = $false
        pep_called = $false
        cleanup = 'NamedPipeServerStream disposed; no persistent pipe created'
        note = 'Requires a unique MSSE-* pipe observation during the monitor scan window. Exact attribution requires source=5, the unique payload prefix, a nonzero event_id, and a nonzero matched rule_id. No enforcement effect is claimed.'
    }

    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $EvidencePath -Encoding UTF8
    Write-Host '[5/6] Proof result'
    $result | ConvertTo-Json -Depth 8
    if (-not $result.passed) { exit 2 }
}
finally {
    if ($nativePipeHandle -ne [IntPtr]::Zero) { [AegisNativePipeFixture]::Close($nativePipeHandle) }
    Write-Host '[6/6] Native pipe cleanup complete'
}
