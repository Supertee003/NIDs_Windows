# AEGIS C1 (O1) - kernel IPv6 identity-sidecar host proof (E5 lab).
#
# Proves on the real host that the O1 driver build emits IPv6 transport
# records whose payload leads with the 32-byte identity sidecar behind
# AEGIS_EVENT_FLAG_V6_SIDECAR, while IPv4 records keep their old shape.
#
# Ring access is read-only: \\.\AegisWfpDevice is opened with GENERIC_READ
# and only GET_STATS / READ_EVENTS are issued (never BLOCK_FLOW /
# UNBLOCK_FLOW). The daemon must be stopped because the device handle is
# exclusive (share 0).
#
# Mutating part is hash-pinned with automatic rollback:
#   test-sign evidence copy -> stop AegisNids -> stop AegisWfp ->
#   install signed candidate -> start driver -> drain baseline ->
#   drive IPv6 + IPv4 loopback traffic -> parse ring bytes ->
#   restore pinned baseline driver -> restart daemon -> verify gate closed
#   and forensic hash chain.
#
# Run elevated:
#   powershell -ExecutionPolicy Bypass -File scripts\c1_e5_sidecar_proof.ps1
# Optional cross-host marker (guest console kit already running a 443
# listener):
#   ... -GuestIPv6 fe80::1234:5678:9abc:def0

[CmdletBinding()]
param(
    [string]$DriverSource = '',
    [string]$EvidenceDir = '',
    [string]$GuestIPv6 = '',
    [double]$SettleSeconds = 1,
    [string]$ExpectedUnsignedSha = 'A583B630BCE55C7FBDE6B29B59657BABD0BD00910151F9257147F20DDE96732C',
    [string]$BaseDriverSha = '49E65BB12B4FC164F0B0C255AC75CDFA096F17AC77B056586BF16891FCDABE8C',
    [string]$BaseDaemonSha = '464E765BAED95C47C0ECCABCC4C47EF682D96762A8C44B329B7B536AB656BC61'
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo
if (-not $DriverSource) { $DriverSource = Join-Path $repo 'build\x64\wfp\aegis_wfp.sys' }
if (-not $EvidenceDir) { $EvidenceDir = Join-Path $repo 'admin-evidence\c1-e5-20261029' }
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$transcript = Join-Path $EvidenceDir ("c1-e5-sidecar-proof-{0}.log" -f $stamp)
$resultPath = Join-Path $EvidenceDir ("c1-e5-sidecar-result-{0}.json" -f $stamp)
$unsignedCopy = Join-Path $EvidenceDir 'aegis_wfp_v6_sidecar_unsigned.sys'
$signedCopy = Join-Path $EvidenceDir 'aegis_wfp_v6_sidecar_signed.sys'
$backup = Join-Path $EvidenceDir 'aegis_wfp_pre_v6_sidecar_49e65bb1.sys'

$driverTarget = Join-Path $env:SystemRoot 'System32\drivers\aegis_wfp.sys'
$daemonTarget = 'C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe'
$device = '\\.\AegisWfpDevice'
$IOCTL_READ_EVENTS = [Convert]::ToUInt32('00126000', 16)
$IOCTL_GET_STATS = [Convert]::ToUInt32('00126008', 16)
$EVENT_HEADER_SIZE = 48
$V6_SIDECAR_SIZE = 32
$GENERIC_READ = [Convert]::ToUInt32('80000000', 16)
$OPEN_EXISTING = [Convert]::ToUInt32('3', 16)
$INVALID_HANDLE_VALUE = [IntPtr](-1)

if (-not ('Aegis.C1E5.Native' -as [type])) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
namespace Aegis.C1E5 {
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

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "=== $Message ==="
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Get-Sha256Safe([string]$Path) {
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
    } catch {
        return $null
    }
}

function Wait-ServiceState([string]$Name, [string]$Desired, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($service -and $service.Status.ToString() -eq $Desired) { return $true }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Invoke-AegisJson([string[]]$Command) {
    $raw = & python @Command 2>&1 | Out-String
    $start = $raw.IndexOf('{')
    if ($start -lt 0) { throw "No JSON response from $($Command -join ' '):`n$raw" }
    return ($raw.Substring($start) | ConvertFrom-Json)
}

function Get-GateSnapshot {
    $gate = Invoke-AegisJson @('tools/aegisctl.py', 'enforce', 'status')
    return [pscustomobject]@{
        prevention_gate      = [string]$gate.prevention_gate
        host_effect_capable  = [bool]$gate.host_effect_capable
        host_effect_confirmed = [bool]$gate.host_effect_confirmed
        enforcement_mode     = [string]$gate.enforcement_mode
    }
}

function Wait-ControlReady([int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    $last = ''
    do {
        try {
            $verify = Invoke-AegisJson @('tools/aegisctl.py', 'forensics', 'verify', '--json')
            if ($verify.verified -eq $true) { return $verify }
            $last = "verified=$($verify.verified)"
        } catch {
            $last = $_.Exception.Message
        }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    throw "Control plane did not become ready within $Seconds seconds. Last result: $last"
}

function Read-Stats([IntPtr]$Handle) {
    $out = New-Object byte[] 24
    [uint32]$returned = 0
    $ok = [Aegis.C1E5.Native]::DeviceIoControl($Handle, $IOCTL_GET_STATS, $null, 0, $out, $out.Length, [ref]$returned, [IntPtr]::Zero)
    if (-not $ok) { throw "GET_STATS failed Win32=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    if ($returned -lt 24) { throw "GET_STATS returned $returned bytes, expected 24" }
    return [pscustomobject]@{
        total_events_written = [BitConverter]::ToUInt32($out, 0)
        total_drops          = [BitConverter]::ToUInt32($out, 4)
        total_bytes_written  = [BitConverter]::ToUInt32($out, 8)
        total_bytes_read     = [BitConverter]::ToUInt32($out, 12)
        current_used_bytes   = [BitConverter]::ToUInt32($out, 16)
    }
}

function Read-Events([IntPtr]$Handle) {
    $out = New-Object byte[] 65536
    [uint32]$returned = 0
    $ok = [Aegis.C1E5.Native]::DeviceIoControl($Handle, $IOCTL_READ_EVENTS, $null, 0, $out, $out.Length, [ref]$returned, [IntPtr]::Zero)
    if (-not $ok) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($err -ne 0) { return [pscustomobject]@{ bytes = 0; win32_error = $err; data = @() } }
    }
    return [pscustomobject]@{ bytes = $returned; win32_error = 0; data = $out }
}

function New-RingState {
    return [pscustomobject]@{
        frames               = 0
        v4_frames            = 0
        v4_flagged           = 0
        v4_attributed        = 0
        v6_frames            = 0
        v6_attributed        = 0
        v6_identity_mismatch = 0
        v6_short_claim       = 0
        oversize_claim       = 0
        trailing_bytes       = 0
        identities           = @{}
        v6_samples           = New-Object System.Collections.Generic.List[object]
        v4_samples           = New-Object System.Collections.Generic.List[object]
        v6_attributed_samples = New-Object System.Collections.Generic.List[object]
        v4_attributed_samples = New-Object System.Collections.Generic.List[object]
        v6_raw_count         = 0
    }
}

function Format-Ipv6([byte[]]$Bytes, [int]$Offset) {
    $slice = New-Object byte[] 16
    [Array]::Copy($Bytes, $Offset, $slice, 0, 16)
    return ([System.Net.IPAddress]::new([byte[]]$slice)).ToString()
}

function Parse-RingBatch {
    param(
        [byte[]]$Bytes,
        [uint32]$ByteCount,
        [object]$State,
        [int[]]$ProbePorts
    )
    $offset = 0
    while ($offset + $EVENT_HEADER_SIZE -le $ByteCount) {
        $flags = $Bytes[$offset + 19]
        $payloadLength = [BitConverter]::ToUInt32($Bytes, $offset + 20)
        if ($payloadLength -gt 4096) {
            # The driver reader resets the ring on such a claim; an O1 record
            # can never produce one (body budget shrinks by the sidecar).
            $State.oversize_claim++
            break
        }
        $recordSize = $EVENT_HEADER_SIZE + [int]$payloadLength
        if ($offset + $recordSize -gt $ByteCount) { break }

        $sport = [int][BitConverter]::ToUInt16($Bytes, $offset + 12)
        $dport = [int][BitConverter]::ToUInt16($Bytes, $offset + 14)
        $attributed = $false
        if ($ProbePorts.Count -gt 0) {
            $attributed = (($ProbePorts -contains $sport) -or ($ProbePorts -contains $dport))
        }
        $hasSidecar = (($flags -band 0x01) -ne 0)
        $State.frames++

        if (-not $hasSidecar) {
            $State.v4_frames++
            if ($attributed) { $State.v4_attributed++ }
            $needGeneral = ($State.v4_samples.Count -lt 20)
            $needAttributed = ($attributed -and $State.v4_attributed_samples.Count -lt 10)
            if ($needGeneral -or $needAttributed) {
                $sample = [pscustomobject]@{
                    src_ip        = ('{0}.{1}.{2}.{3}' -f $Bytes[$offset + 7], $Bytes[$offset + 6], $Bytes[$offset + 5], $Bytes[$offset + 4])
                    dst_ip        = ('{0}.{1}.{2}.{3}' -f $Bytes[$offset + 11], $Bytes[$offset + 10], $Bytes[$offset + 9], $Bytes[$offset + 8])
                    sport         = $sport
                    dport         = $dport
                    protocol      = [int]$Bytes[$offset + 16]
                    direction     = [int]$Bytes[$offset + 17]
                    layer_id      = [int]$Bytes[$offset + 18]
                    flags         = [int]$flags
                    payload_length = [int]$payloadLength
                    attributed    = $attributed
                }
                if ($needGeneral) { $State.v4_samples.Add($sample) | Out-Null }
                if ($needAttributed) { $State.v4_attributed_samples.Add($sample) | Out-Null }
            }
        } else {
            $State.v6_frames++
            if ($attributed) { $State.v6_attributed++ }
            if ($payloadLength -lt $V6_SIDECAR_SIZE) {
                $State.v6_short_claim++
            } else {
                # Header u32 identity must be the BE value of the sidecar's
                # first four bytes; on little-endian memory that stores the
                # four bytes reversed. Compare bytes directly (endian-proof).
                $identityOk =
                    ($Bytes[$offset + 4]  -eq $Bytes[$offset + 51]) -and
                    ($Bytes[$offset + 5]  -eq $Bytes[$offset + 50]) -and
                    ($Bytes[$offset + 6]  -eq $Bytes[$offset + 49]) -and
                    ($Bytes[$offset + 7]  -eq $Bytes[$offset + 48]) -and
                    ($Bytes[$offset + 8]  -eq $Bytes[$offset + 67]) -and
                    ($Bytes[$offset + 9]  -eq $Bytes[$offset + 66]) -and
                    ($Bytes[$offset + 10] -eq $Bytes[$offset + 65]) -and
                    ($Bytes[$offset + 11] -eq $Bytes[$offset + 64])
                if (-not $identityOk) { $State.v6_identity_mismatch++ }

                $prefix = ('{0:X2}{1:X2}{2:X2}{3:X2}' -f $Bytes[$offset + 48], $Bytes[$offset + 49], $Bytes[$offset + 50], $Bytes[$offset + 51])
                if ($State.identities.ContainsKey($prefix)) {
                    $State.identities[$prefix] = [int]$State.identities[$prefix] + 1
                } else {
                    $State.identities[$prefix] = 1
                }

                $needGeneral = ($State.v6_samples.Count -lt 40)
                $needAttributed = ($attributed -and $State.v6_attributed_samples.Count -lt 20)
                if ($needGeneral -or $needAttributed) {
                    # Keep the exact ring bytes for the first few records so the
                    # evidence JSON carries the sidecar at the byte level, not
                    # only the parsed view. Capped to bound the JSON size.
                    $rawHex = $null
                    $rawTruncated = $false
                    if ($State.v6_raw_count -lt 8) {
                        $State.v6_raw_count++
                        $rawLen = [Math]::Min($recordSize, 512)
                        $rawTruncated = ($recordSize -gt $rawLen)
                        $rawHex = -join ($Bytes[$offset..($offset + $rawLen - 1)] | ForEach-Object { '{0:X2}' -f $_ })
                    }
                    $sample = [pscustomobject]@{
                        src6           = Format-Ipv6 $Bytes ($offset + 48)
                        dst6           = Format-Ipv6 $Bytes ($offset + 64)
                        src_prefix     = $prefix
                        sport          = $sport
                        dport          = $dport
                        protocol       = [int]$Bytes[$offset + 16]
                        direction      = [int]$Bytes[$offset + 17]
                        layer_id       = [int]$Bytes[$offset + 18]
                        flags          = [int]$flags
                        payload_length = [int]$payloadLength
                        body_length    = [int]$payloadLength - $V6_SIDECAR_SIZE
                        record_size    = $recordSize
                        identity_ok    = $identityOk
                        attributed     = $attributed
                        timestamp_raw  = [BitConverter]::ToUInt64($Bytes, $offset + 40)
                        raw_hex        = $rawHex
                        raw_truncated  = $rawTruncated
                    }
                    if ($needGeneral) { $State.v6_samples.Add($sample) | Out-Null }
                    if ($needAttributed) { $State.v6_attributed_samples.Add($sample) | Out-Null }
                }
            }
        }
        $offset += $recordSize
    }
    $State.trailing_bytes += [int]($ByteCount - $offset)
}

function Drain-Ring {
    param([IntPtr]$Handle, [object]$State, [int[]]$ProbePorts)
    $reads = 0
    $bytes = [int64]0
    while ($reads -lt 1024) {
        $batch = Read-Events $Handle
        if ($batch.bytes -le 0) { break }
        $bytes += [int64]$batch.bytes
        Parse-RingBatch -Bytes $batch.data -ByteCount $batch.bytes -State $State -ProbePorts $ProbePorts
        $reads++
        # A short batch does NOT mean the ring is empty: the driver stops
        # before the first record that would not fit the 64 KiB buffer.
        # Keep reading until READ_EVENTS reports no more entries (bytes=0).
    }
    return [pscustomobject]@{ bytes = $bytes; reads = $reads }
}

function Open-Device([int]$Attempts) {
    $lastError = 0
    for ($i = 0; $i -lt $Attempts; $i++) {
        $h = [Aegis.C1E5.Native]::CreateFile($device, $GENERIC_READ, 0, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
        if ($h -ne $INVALID_HANDLE_VALUE) { return $h }
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Start-Sleep -Milliseconds 500
    }
    throw "Cannot open $device with GENERIC_READ after $Attempts attempts (Win32=$lastError). Is AegisNids still holding the exclusive handle?"
}

function Invoke-Tcp6ListenerProbe {
    param([System.Net.IPAddress]$BindAddress, [string]$Label)
    $result = [pscustomobject]@{
        label       = $Label
        family      = 'ipv6'
        target      = $BindAddress.ToString()
        bound_port  = 0
        client_port = 0
        ok          = $false
        error       = ''
    }
    $listener = $null
    $client = $null
    $accepted = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new($BindAddress, 0)
        $listener.Start()
        $bound = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        $result.bound_port = $bound
        $acceptTask = $listener.AcceptTcpClientAsync()
        $client = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetworkV6)
        $connectTask = $client.ConnectAsync($BindAddress, $bound)
        if (-not $connectTask.Wait(3000)) { throw 'connect timeout' }
        if ($connectTask.IsFaulted) { throw $connectTask.Exception.GetBaseException().Message }
        if (-not $acceptTask.Wait(3000)) { throw 'accept timeout' }
        $accepted = $acceptTask.Result
        $result.client_port = ([System.Net.IPEndPoint]$client.Client.LocalEndPoint).Port
        $stream = $client.GetStream()
        $payload = [Text.Encoding]::ASCII.GetBytes("AEGIS-C1-E5-$Label")
        $stream.Write($payload, 0, $payload.Length)
        $stream.Flush()
        $stream.Close()
        $result.ok = $true
    } catch {
        $result.error = $_.Exception.Message
    } finally {
        if ($accepted) { $accepted.Close() }
        if ($client) { $client.Close() }
        if ($listener) { $listener.Stop() }
    }
    return $result
}

function Invoke-Tcp4ListenerProbe {
    $result = [pscustomobject]@{
        label       = 'tcp4-loopback-regression'
        family      = 'ipv4'
        target      = '127.0.0.1'
        bound_port  = 0
        client_port = 0
        ok          = $false
        error       = ''
    }
    $listener = $null
    $client = $null
    $accepted = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $bound = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        $result.bound_port = $bound
        $acceptTask = $listener.AcceptTcpClientAsync()
        $client = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetwork)
        $connectTask = $client.ConnectAsync([System.Net.IPAddress]::Loopback, $bound)
        if (-not $connectTask.Wait(3000)) { throw 'connect timeout' }
        if ($connectTask.IsFaulted) { throw $connectTask.Exception.GetBaseException().Message }
        if (-not $acceptTask.Wait(3000)) { throw 'accept timeout' }
        $accepted = $acceptTask.Result
        $result.client_port = ([System.Net.IPEndPoint]$client.Client.LocalEndPoint).Port
        $stream = $client.GetStream()
        $payload = [Text.Encoding]::ASCII.GetBytes('AEGIS-C1-E5-V4')
        $stream.Write($payload, 0, $payload.Length)
        $stream.Flush()
        $stream.Close()
        $result.ok = $true
    } catch {
        $result.error = $_.Exception.Message
    } finally {
        if ($accepted) { $accepted.Close() }
        if ($client) { $client.Close() }
        if ($listener) { $listener.Stop() }
    }
    return $result
}

function Invoke-Ping6([string]$Target, [string]$Label) {
    $output = & ping.exe -6 -n 2 -w 1500 $Target 2>&1 | Out-String
    return [pscustomobject]@{
        label  = $Label
        family = 'ipv6'
        target = $Target
        ok     = ($output -match 'Reply from')
        output = (($output.Trim() -split "`r?`n") | Select-Object -First 6) -join ' | '
    }
}

function Invoke-Udp6Probe([System.Net.IPAddress]$Target, [int]$Port, [string]$Label) {
    $result = [pscustomobject]@{ label = $Label; family = 'ipv6'; target = "$Target/$Port"; local_port = 0; ok = $false; error = '' }
    $udp = $null
    try {
        $udp = [System.Net.Sockets.UdpClient]::new([System.Net.Sockets.AddressFamily]::InterNetworkV6)
        $udp.Client.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::IPv6Any, 0))
        $result.local_port = ([System.Net.IPEndPoint]$udp.Client.LocalEndPoint).Port
        $payload = [Text.Encoding]::ASCII.GetBytes("AEGIS-C1-E5-$Label")
        [void]$udp.Send($payload, $payload.Length, [System.Net.IPEndPoint]::new($Target, $Port))
        $result.ok = $true
    } catch {
        $result.error = $_.Exception.Message
    } finally {
        if ($udp) { $udp.Close() }
    }
    return $result
}

function Invoke-Tcp6Connect {
    param([string]$Target, [int]$Port, [string]$Label)
    $result = [pscustomobject]@{ label = $Label; family = 'ipv6'; target = "$Target/$Port"; local_port = 0; ok = $false; error = '' }
    $client = $null
    try {
        $address = [System.Net.IPAddress]::Parse($Target)
        $client = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetworkV6)
        $task = $client.ConnectAsync($address, $Port)
        if (-not $task.Wait(3000)) { throw 'connect timeout' }
        if ($task.IsFaulted) { throw $task.Exception.GetBaseException().Message }
        $result.local_port = ([System.Net.IPEndPoint]$client.Client.LocalEndPoint).Port
        $result.ok = $true
    } catch {
        $result.error = $_.Exception.Message
    } finally {
        if ($client) { $client.Close() }
    }
    return $result
}

function Get-HostLinkLocal6 {
    $addr = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -like 'fe80::*' -and $_.InterfaceAlias -match 'VMnet1' } |
        Select-Object -First 1
    if (-not $addr) { return $null }
    $text = [string]$addr.IPAddress
    # Get-NetIPAddress already appends the scope id on some builds; never
    # append a second one (fe80::x%24%24 is not parseable).
    if ($text -match '%') { return [System.Net.IPAddress]::Parse($text) }
    return [System.Net.IPAddress]::Parse(("{0}%{1}" -f $text, $addr.InterfaceIndex))
}

function Invoke-TrafficSuite {
    param([string]$GuestTarget)
    $probes = New-Object System.Collections.Generic.List[object]
    $ports = New-Object System.Collections.Generic.List[int]

    $probe = Invoke-Tcp6ListenerProbe -BindAddress ([System.Net.IPAddress]::IPv6Loopback) -Label 'tcp6-loopback'
    $probes.Add($probe)
    if ($probe.bound_port -gt 0) { $ports.Add([int]$probe.bound_port) }
    if ($probe.client_port -gt 0) { $ports.Add([int]$probe.client_port) }

    $host6 = Get-HostLinkLocal6
    if ($host6) {
        $probe = Invoke-Tcp6ListenerProbe -BindAddress $host6 -Label 'tcp6-host-linklocal'
        $probes.Add($probe)
        if ($probe.bound_port -gt 0) { $ports.Add([int]$probe.bound_port) }
        if ($probe.client_port -gt 0) { $ports.Add([int]$probe.client_port) }
    } else {
        $probes.Add([pscustomobject]@{ label = 'tcp6-host-linklocal'; family = 'ipv6'; target = ''; bound_port = 0; client_port = 0; ok = $false; error = 'no VMnet1 fe80 address found' })
    }

    $probes.Add((Invoke-Ping6 -Target '::1' -Label 'icmp6-loopback'))

    $udp = Invoke-Udp6Probe -Target ([System.Net.IPAddress]::IPv6Loopback) -Port 47832 -Label 'udp6-loopback'
    $probes.Add($udp)
    if ($udp.local_port -gt 0) { $ports.Add([int]$udp.local_port) }

    if ($GuestTarget) {
        $probes.Add((Invoke-Ping6 -Target $GuestTarget -Label 'icmp6-guest'))
        $guestTcp = Invoke-Tcp6Connect -Target $GuestTarget -Port 443 -Label 'tcp6-guest-443'
        $probes.Add($guestTcp)
        if ($guestTcp.local_port -gt 0) { $ports.Add([int]$guestTcp.local_port) }
        if ($guestTcp.ok) { $ports.Add(443) }
    }

    $v4 = Invoke-Tcp4ListenerProbe
    $probes.Add($v4)
    if ($v4.bound_port -gt 0) { $ports.Add([int]$v4.bound_port) }
    if ($v4.client_port -gt 0) { $ports.Add([int]$v4.client_port) }

    return [pscustomobject]@{
        probes = $probes
        ports  = @($ports | Sort-Object -Unique)
    }
}

# ---------------------------------------------------------------------------
# Preflight (read-only)
# ---------------------------------------------------------------------------
Start-Transcript -Path $transcript -Force | Out-Null

$head = (& git -C $repo rev-parse HEAD | Out-String).Trim()
$startedAt = (Get-Date).ToString('o')
$result = [ordered]@{
    proof        = 'c1_o1_kernel_ipv6_sidecar_e5'
    level_claim  = 'E5'
    head         = $head
    started_at   = $startedAt
    host         = $env:COMPUTERNAME
    passed       = $false
    error        = $null
}

$handle = [IntPtr]::Zero
$candidateInstalled = $false
$daemonStopped = $false
$capture = $null
$traffic = $null
$rollback = $null

try {
    Write-Step 'Preflight: elevation and pins'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this proof from elevated PowerShell (driver sign + service control).'
    }
    if (-not (Test-Path -LiteralPath $DriverSource -PathType Leaf)) { throw "Candidate driver missing: $DriverSource" }

    $unsignedHash = Get-Sha256 $DriverSource
    Write-Host "candidate source: $DriverSource"
    Write-Host "candidate unsigned SHA-256: $unsignedHash ($((Get-Item -LiteralPath $DriverSource).Length) bytes)"
    if ($unsignedHash -ne $ExpectedUnsignedSha) {
        throw "Candidate driver hash $unsignedHash does not match the O1 build pin $ExpectedUnsignedSha. Rebuild before proving."
    }

    $nids = Get-Service -Name AegisNids -ErrorAction SilentlyContinue
    $wfp = Get-Service -Name AegisWfp -ErrorAction SilentlyContinue
    if (-not $nids -or -not $wfp) { throw 'AegisNids and AegisWfp services must both be installed.' }
    if ($nids.Status -ne 'Running' -or $wfp.Status -ne 'Running') {
        throw "Both services must be running before the proof (AegisNids=$($nids.Status), AegisWfp=$($wfp.Status))."
    }
    $installedDriverHash = Get-Sha256 $driverTarget
    $installedDaemonHash = Get-Sha256 $daemonTarget
    Write-Host "installed driver SHA-256: $installedDriverHash"
    Write-Host "installed daemon SHA-256: $installedDaemonHash"
    if ($installedDriverHash -ne $BaseDriverSha) {
        throw "Installed driver $installedDriverHash is not the pinned baseline $BaseDriverSha. Refusing to swap."
    }
    if ($installedDaemonHash -ne $BaseDaemonSha) {
        throw "Installed daemon $installedDaemonHash is not the pinned baseline $BaseDaemonSha. Refusing to swap."
    }
    $gateBefore = Get-GateSnapshot
    if ($gateBefore.prevention_gate -ne 'closed' -or $gateBefore.host_effect_capable) {
        throw "Prevention gate must be closed before the proof (got $($gateBefore.prevention_gate), host_effect_capable=$($gateBefore.host_effect_capable))."
    }
    $result.preflight = [ordered]@{
        elevated             = $true
        candidate_unsigned   = $unsignedHash
        installed_driver     = $installedDriverHash
        installed_daemon     = $installedDaemonHash
        gate                 = $gateBefore
        services             = @{ AegisNids = [string]$nids.Status; AegisWfp = [string]$wfp.Status }
    }

    Write-Step 'Preserve unsigned build copy and test-sign an evidence copy'
    Copy-Item -LiteralPath $DriverSource -Destination $unsignedCopy -Force
    if ((Get-Sha256 $unsignedCopy) -ne $ExpectedUnsignedSha) { throw 'Unsigned evidence copy hash mismatch.' }
    Copy-Item -LiteralPath $unsignedCopy -Destination $signedCopy -Force
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'scripts\wfp_sign.ps1') -SysPath $signedCopy | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "wfp_sign.ps1 failed (exit $LASTEXITCODE)." }
    $signature = Get-AuthenticodeSignature -LiteralPath $signedCopy
    if ($signature.Status -ne 'Valid') { throw "Signed copy status is $($signature.Status), expected Valid." }
    $signedHash = Get-Sha256 $signedCopy
    $signedSize = (Get-Item -LiteralPath $signedCopy).Length
    Write-Host "signed candidate SHA-256: $signedHash ($signedSize bytes)"
    Write-Host "signer: $($signature.SignerCertificate.Subject)"
    $result.candidate = [ordered]@{
        unsigned_sha256 = $ExpectedUnsignedSha
        signed_sha256   = $signedHash
        signed_bytes    = $signedSize
        signer          = [string]$signature.SignerCertificate.Subject
        unsigned_copy   = $unsignedCopy
        signed_copy     = $signedCopy
    }

    Write-Step 'Pin rollback backup of the deployed baseline driver'
    if (Test-Path -LiteralPath $backup) {
        if ((Get-Sha256 $backup) -ne $BaseDriverSha) {
            throw "Existing rollback backup $backup does not match the baseline pin. Refusing to overwrite it."
        }
        Write-Host "reusing verified rollback backup: $backup"
    } else {
        Copy-Item -LiteralPath $driverTarget -Destination $backup -Force
    }
    if ((Get-Sha256 $backup) -ne $BaseDriverSha) { throw 'Rollback backup hash verification failed.' }
    $result.backup = [ordered]@{ path = $backup; sha256 = (Get-Sha256 $backup) }

    Write-Step 'Stop AegisNids (free the exclusive WFP device handle)'
    & sc.exe stop AegisNids | Out-Host
    if (-not (Wait-ServiceState 'AegisNids' 'Stopped' 45)) { throw 'AegisNids did not stop.' }
    $daemonStopped = $true
    Start-Sleep -Seconds 1
    $leftover = Get-Process -Name aegis_nids -ErrorAction SilentlyContinue
    if ($leftover) {
        $leftover | ForEach-Object { Write-Warning "aegis_nids.exe still running pid=$($_.Id); waiting" }
        Start-Sleep -Seconds 3
        if (Get-Process -Name aegis_nids -ErrorAction SilentlyContinue) { throw 'aegis_nids.exe is still running; device handle would stay busy.' }
    }
    Write-Host 'daemon stopped; WFP device is free'

    Write-Step 'Stop AegisWfp and install the signed candidate'
    & sc.exe stop AegisWfp | Out-Host
    if (-not (Wait-ServiceState 'AegisWfp' 'Stopped' 45)) { throw 'AegisWfp did not stop.' }
    Copy-Item -LiteralPath $signedCopy -Destination $driverTarget -Force
    $candidateInstalled = $true
    $installedCandidateHash = Get-Sha256 $driverTarget
    if ($installedCandidateHash -ne $signedHash) { throw "Installed candidate hash $installedCandidateHash != signed copy $signedHash." }
    Write-Host "candidate installed at $driverTarget sha256=$installedCandidateHash"
    & sc.exe start AegisWfp | Out-Host
    if (-not (Wait-ServiceState 'AegisWfp' 'Running' 45)) { throw 'AegisWfp did not start with the O1 candidate.' }
    Write-Host 'O1 candidate driver RUNNING'
    $result.candidate.installed_sha256 = (Get-Sha256 $driverTarget)
    $result.candidate.driver_running = $true

    Write-Step 'Open WFP device (GENERIC_READ, exclusive) and drain baseline'
    $handle = Open-Device 30
    $statsBefore = Read-Stats $handle
    $baselineState = New-RingState
    $baselineDrain = Drain-Ring -Handle $handle -State $baselineState -ProbePorts @()
    Write-Host "baseline events=$($statsBefore.total_events_written) drops=$($statsBefore.total_drops) bytes=$($statsBefore.total_bytes_written) used=$($statsBefore.current_used_bytes)"
    Write-Host "baseline drain bytes=$($baselineDrain.bytes) frames=$($baselineState.frames)"

    Write-Step 'Drive IPv6 (and IPv4 regression) traffic'
    $guestTarget = $null
    if ($GuestIPv6) {
        $guestTarget = $GuestIPv6.Trim()
        # Scope id only applies to link-local addresses; a global address is
        # used as-is (appending %24 there would break the connect).
        if ($guestTarget -match '^(?i)fe80:' -and $guestTarget -notmatch '%') {
            $guestTarget = "$guestTarget%24"
        }
    }
    $traffic = $null
    $state = New-RingState
    $drained = $null
    $statsAfterTraffic = $null
    $statsAfterDrain = $null
    $attempts = 0
    $maxAttempts = 3
    while ($attempts -lt $maxAttempts) {
        $attempts++

        # Empty the ring immediately before probing so the probe records sit
        # at the read head and cannot be crowded out by background traffic.
        $preState = New-RingState
        $preDrain = Drain-Ring -Handle $handle -State $preState -ProbePorts @()
        if ($preDrain.bytes -gt 0) {
            Write-Host "pre-probe drain attempt=$attempts bytes=$($preDrain.bytes) frames=$($preState.frames)"
        }

        $traffic = Invoke-TrafficSuite -GuestTarget $guestTarget
        foreach ($probe in $traffic.probes) {
            $status = if ($probe.ok) { 'OK' } else { "FAILED: $($probe.error)" }
            Write-Host ("  {0}: {1} {2}" -f $probe.label, $probe.target, $status)
        }
        Write-Host ("probe ports: {0}" -f ($traffic.ports -join ','))
        Start-Sleep -Milliseconds ([int]($SettleSeconds * 1000))

        $statsAfterTraffic = Read-Stats $handle
        $state = New-RingState
        $drained = Drain-Ring -Handle $handle -State $state -ProbePorts ([int[]]$traffic.ports)
        $statsAfterDrain = Read-Stats $handle
        Write-Host "attempt=$attempts captured bytes=$($drained.bytes) reads=$($drained.reads) frames=$($state.frames) v6=$($state.v6_frames) v6_attributed=$($state.v6_attributed) v4=$($state.v4_frames) v4_attributed=$($state.v4_attributed)"
        Write-Host "defects: identity_mismatch=$($state.v6_identity_mismatch) short_claim=$($state.v6_short_claim) oversize_claim=$($state.oversize_claim) trailing_bytes=$($state.trailing_bytes)"
        Write-Host ("v6 identity prefixes: {0}" -f (($state.identities.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '))
        if ($state.v6_attributed -gt 0 -and $state.v4_attributed -gt 0) { break }
        if ($attempts -lt $maxAttempts) {
            Write-Warning "attempt $attempts did not attribute both probe families; retrying after a full drain"
        }
    }

    $capture = [ordered]@{
        stats_before       = $statsBefore
        stats_after        = $statsAfterTraffic
        stats_after_drain  = $statsAfterDrain
        attempts           = $attempts
        baseline           = @{ bytes = $baselineDrain.bytes; reads = $baselineDrain.reads; frames = $baselineState.frames }
        drained            = @{ bytes = $drained.bytes; reads = $drained.reads }
        frames             = $state.frames
        v4_frames          = $state.v4_frames
        v4_flagged         = $state.v4_flagged
        v4_attributed      = $state.v4_attributed
        v6_frames          = $state.v6_frames
        v6_attributed      = $state.v6_attributed
        v6_identity_mismatch = $state.v6_identity_mismatch
        v6_short_claim     = $state.v6_short_claim
        oversize_claim     = $state.oversize_claim
        trailing_bytes     = $state.trailing_bytes
        identities         = $state.identities
        # PS 5.1: @() over a List[object] throws "Argument types do not
        # match"; ToArray() is the reliable conversion.
        v6_samples         = $state.v6_samples.ToArray()
        v6_attributed_samples = $state.v6_attributed_samples.ToArray()
        v4_samples         = $state.v4_samples.ToArray()
        v4_attributed_samples = $state.v4_attributed_samples.ToArray()
        traffic            = $traffic
    }

    # Close the device before any service control so the driver can stop.
    [Aegis.C1E5.Native]::CloseHandle($handle) | Out-Null
    $handle = [IntPtr]::Zero
} catch {
    $result.error = $_.Exception.Message
    Write-Host "PROOF ERROR: $($result.error)" -ForegroundColor Red
} finally {
    if ($handle -ne [IntPtr]::Zero) {
        [Aegis.C1E5.Native]::CloseHandle($handle) | Out-Null
        $handle = [IntPtr]::Zero
    }
    if ($candidateInstalled) {
        Write-Step 'Rollback: restore pinned baseline driver and daemon'
        $steps = New-Object System.Collections.Generic.List[string]
        $rollbackOk = $true
        $rollbackError = ''
        try {
            $wfpNow = Get-Service -Name AegisWfp -ErrorAction SilentlyContinue
            if ($wfpNow -and $wfpNow.Status -ne 'Stopped') {
                & sc.exe stop AegisWfp | Out-Host
                if (-not (Wait-ServiceState 'AegisWfp' 'Stopped' 45)) { throw 'AegisWfp did not stop for rollback.' }
            }
            $steps.Add('driver stopped')
            Copy-Item -LiteralPath $backup -Destination $driverTarget -Force
            $restoredHash = Get-Sha256 $driverTarget
            if ($restoredHash -ne $BaseDriverSha) { throw "Restored driver hash $restoredHash != baseline $BaseDriverSha." }
            $steps.Add("baseline driver restored sha256=$restoredHash")
            & sc.exe start AegisWfp | Out-Host
            if (-not (Wait-ServiceState 'AegisWfp' 'Running' 45)) { throw 'AegisWfp did not restart after rollback.' }
            $steps.Add('driver running')

            if ($daemonStopped) {
                & sc.exe start AegisNids | Out-Host
                if (-not (Wait-ServiceState 'AegisNids' 'Running' 60)) { throw 'AegisNids did not restart after rollback.' }
                $steps.Add('daemon running')
            }
            $forensics = Wait-ControlReady 60
            $steps.Add("control ready verified=$($forensics.verified) integrity=$($forensics.integrity)")
            $gateAfter = Get-GateSnapshot
            if ($gateAfter.prevention_gate -ne 'closed' -or $gateAfter.host_effect_capable) {
                throw "Post-rollback gate is not closed (got $($gateAfter.prevention_gate), host_effect_capable=$($gateAfter.host_effect_capable))."
            }
            $steps.Add('prevention gate closed')
            $rollback = [ordered]@{
                ok               = $true
                steps            = @($steps)
                driver_sha256    = (Get-Sha256 $driverTarget)
                daemon_sha256    = (Get-Sha256 $daemonTarget)
                gate             = $gateAfter
                forensics        = $forensics
                services         = @{ AegisNids = [string](Get-Service AegisNids).Status; AegisWfp = [string](Get-Service AegisWfp).Status }
            }
        } catch {
            $rollbackOk = $false
            $rollbackError = $_.Exception.Message
            $steps.Add("ROLLBACK ERROR: $rollbackError")
            Write-Host "ROLLBACK FAILED: $rollbackError" -ForegroundColor Red
            $rollback = [ordered]@{
                ok            = $false
                steps         = @($steps)
                error         = $rollbackError
                driver_sha256 = (Get-Sha256Safe $driverTarget)
                daemon_sha256 = (Get-Sha256Safe $daemonTarget)
            }
        }
        if (-not $rollbackOk) { $result.error = "ROLLBACK FAILED: $rollbackError" }
    } elseif ($daemonStopped) {
        # Failure before the candidate touched the driver: just restart the daemon.
        Write-Step 'Restart daemon (candidate was never installed)'
        try {
            & sc.exe start AegisNids | Out-Host
            if (-not (Wait-ServiceState 'AegisNids' 'Running' 60)) { throw 'AegisNids did not restart.' }
            $rollback = [ordered]@{ ok = $true; steps = @('candidate not installed; daemon restarted'); daemon_sha256 = (Get-Sha256Safe $daemonTarget) }
        } catch {
            $restartError = $_.Exception.Message
            $result.error = "DAEMON RESTART FAILED: $restartError"
            $rollback = [ordered]@{ ok = $false; steps = @('candidate not installed; daemon restart failed'); error = $restartError; daemon_sha256 = (Get-Sha256Safe $daemonTarget) }
        }
    }
}

# ---------------------------------------------------------------------------
# Evaluate and persist
# ---------------------------------------------------------------------------
$criteria = [ordered]@{}
$criteria['candidate_signed_and_installed'] = ($null -ne $result.candidate -and $result.candidate.Contains('signed_sha256'))
$criteria['driver_ran'] = ($null -ne $result.candidate -and $result.candidate.Contains('driver_running'))
if ($capture) {
    $criteria['ring_bytes_read'] = ([int64]$capture.drained.bytes -gt 0)
    $criteria['v6_sidecar_frames'] = ([int]$capture.v6_frames -ge 1)
    $criteria['v6_attributed_to_probe'] = ([int]$capture.v6_attributed -ge 1)
    $criteria['v6_identity_matches_sidecar'] = ([int]$capture.v6_identity_mismatch -eq 0 -and [int]$capture.v6_frames -ge 1)
    $criteria['v6_no_short_claim'] = ([int]$capture.v6_short_claim -eq 0)
    $criteria['no_oversize_claim'] = ([int]$capture.oversize_claim -eq 0)
    $criteria['ring_alignment_clean'] = ([int]$capture.trailing_bytes -eq 0)
    $criteria['v4_regression_frames'] = ([int]$capture.v4_frames -ge 1)
    $criteria['v4_regression_attributed'] = ([int]$capture.v4_attributed -ge 1)
    $criteria['v4_unflagged'] = ([int]$capture.v4_flagged -eq 0)
} else {
    $criteria['ring_bytes_read'] = $false
    $criteria['v6_sidecar_frames'] = $false
    $criteria['v6_attributed_to_probe'] = $false
    $criteria['v6_identity_matches_sidecar'] = $false
    $criteria['v6_no_short_claim'] = $false
    $criteria['no_oversize_claim'] = $false
    $criteria['ring_alignment_clean'] = $false
    $criteria['v4_regression_frames'] = $false
    $criteria['v4_regression_attributed'] = $false
    $criteria['v4_unflagged'] = $false
}
$criteria['rollback_restored_baseline'] = ($null -ne $rollback -and $rollback.Contains('driver_sha256') -and $rollback.driver_sha256 -eq $BaseDriverSha)
$criteria['daemon_baseline_restored'] = ($null -ne $rollback -and $rollback.Contains('daemon_sha256') -and $rollback.daemon_sha256 -eq $BaseDaemonSha)
$criteria['prevention_gate_closed_after'] = ($null -ne $rollback -and $rollback.Contains('gate') -and $rollback.gate.prevention_gate -eq 'closed')
$criteria['rollback_ok'] = ($null -ne $rollback -and [bool]$rollback.ok)
$nonzeroIdentity = $false
if ($capture) {
    foreach ($key in $capture.identities.Keys) {
        if ($key -ne '00000000') { $nonzeroIdentity = $true }
    }
}
$criteria['v6_nonzero_identity_prefix'] = $nonzeroIdentity

$failedCriteria = @($criteria.Keys | Where-Object { -not $criteria[$_] })
$result.criteria = $criteria
$result.passed = ($failedCriteria.Count -eq 0 -and -not $result.error)
$result.failed_criteria = $failedCriteria
$result.capture = $capture
$result.rollback = $rollback
$result.host_effect = 'none'
$result.prevention_gate = 'closed'
$result.note = 'E5 covers kernel ring emission on this host (driver swap + raw ring bytes). The zig sidecar decoder is proven at E2 (O1-V6-SIDECAR-E2-20261029); the daemon was intentionally left at the pinned baseline build and only stopped to free the exclusive device handle.'
$result.finished_at = (Get-Date).ToString('o')
$result.result_path = $resultPath
$result.transcript = $transcript

$json = $result | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($resultPath, $json, (New-Object System.Text.UTF8Encoding($false)))

Write-Step 'Result'
Write-Host $json
Write-Host ""
if ($result.passed) {
    Write-Host "C1-E5 PASS: kernel IPv6 sidecar observed on the ring ($($capture.v6_frames) v6 frames, $($capture.v6_attributed) attributed); v4 regression $($capture.v4_frames) frames; rollback verified." -ForegroundColor Green
    Stop-Transcript | Out-Null
    exit 0
}
Write-Host "C1-E5 FAIL: failed criteria = $($failedCriteria -join ', ')" -ForegroundColor Yellow
Write-Host "result: $resultPath"
Write-Host "transcript: $transcript"
Stop-Transcript | Out-Null
if ($result.error) { exit 1 }
exit 2
