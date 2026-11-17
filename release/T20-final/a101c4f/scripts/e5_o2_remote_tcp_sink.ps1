# One-shot remote TCP sink for the O2 outbound E5 proof.
# Run on an operator-controlled second machine; bind only to its intended LAN IP.
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ListenAddress,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int]$Port,

    [ValidateRange(10, 900)]
    [int]$TimeoutSeconds = 180,

    [string]$OutputPath = (Join-Path (Get-Location) 'e5-o2-remote-sink.json')
)
$ErrorActionPreference = 'Stop'

$bindIp = $null
if (-not [System.Net.IPAddress]::TryParse($ListenAddress, [ref]$bindIp)) {
    throw "ListenAddress must be a literal IP assigned to this machine: $ListenAddress"
}

$listener = [System.Net.Sockets.TcpListener]::new($bindIp, $Port)
$client = $null
$doc = [ordered]@{
    started_at = [DateTime]::UtcNow.ToString('o')
    listen_address = $bindIp.ToString()
    port = $Port
    peer = $null
    bytes_received = 0
    marker = $null
    received_at = $null
    result = 'waiting'
}

try {
    $listener.Start(1)
    Write-Host "Listening once on $($bindIp.ToString()):$Port for up to $TimeoutSeconds seconds."
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while (-not $listener.Pending()) {
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Timed out waiting for the proof client.' }
        Start-Sleep -Milliseconds 200
    }

    $client = $listener.AcceptTcpClient()
    $doc.peer = $client.Client.RemoteEndPoint.ToString()
    $stream = $client.GetStream()
    $stream.ReadTimeout = 10000
    $buffer = New-Object byte[] 256
    $memory = [System.IO.MemoryStream]::new()
    try {
        while ($true) {
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -eq 0) { break }
            if (($memory.Length + $read) -gt 256) { throw 'Rejected payload larger than 256 bytes.' }
            $memory.Write($buffer, 0, $read)
        }
        $payload = $memory.ToArray()
        $doc.bytes_received = $payload.Length
        $doc.marker = [System.Text.Encoding]::ASCII.GetString($payload)
        $doc.received_at = [DateTime]::UtcNow.ToString('o')
        if ($doc.marker -notmatch '^AEGIS-O2-DIRECTION-[0-9a-f]{32}$') {
            throw 'Received payload does not match the expected O2 marker format.'
        }
        $doc.result = 'marker_received'
    } finally { $memory.Dispose() }
} catch {
    $doc.result = 'error'
    $doc.error = $_.Exception.Message
    throw
} finally {
    if ($client) { $client.Dispose() }
    $listener.Stop()
    $doc.finished_at = [DateTime]::UtcNow.ToString('o')
    $parent = Split-Path -Parent $OutputPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $doc | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    Write-Host "Result=$($doc.result) marker=$($doc.marker) evidence=$OutputPath"
}

if ($doc.result -ne 'marker_received') { exit 1 }
