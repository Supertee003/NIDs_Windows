[CmdletBinding()]
param(
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$rulesCandidates = @(
    (Join-Path $root 'configs\Rules.json'),
    (Join-Path $root 'config\Rules.json')
)
$rulesPath = $rulesCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $rulesPath) { throw 'No canonical Rules.json found in configs\ or config\' }

$rules = Get-Content $rulesPath -Raw -Encoding UTF8 | ConvertFrom-Json
$count = @($rules.nids_rules).Count
if ($count -le 0) { throw "Rules file contains no nids_rules: $rulesPath" }
Write-Host "Rules source: $rulesPath" -ForegroundColor Cyan
Write-Host "Rules on disk: $count" -ForegroundColor Cyan

foreach ($candidate in $rulesCandidates) {
    if (Test-Path $candidate) {
        $hash = (Get-FileHash $candidate -Algorithm SHA256).Hash
        Write-Host "SHA256 $candidate = $hash"
    }
}

if ($ValidateOnly) { exit 0 }

$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'aegis_control', [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None)
try {
    $pipe.Connect(5000)
    $request = '{"command":"rules.reload","payload":{}}'
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($request)
    $pipe.Write($bytes, 0, $bytes.Length)
    $pipe.Flush()

    $buffer = New-Object byte[] 65536
    $received = New-Object System.IO.MemoryStream
    do {
        $n = $pipe.Read($buffer, 0, $buffer.Length)
        if ($n -le 0) { break }
        $received.Write($buffer, 0, $n)
        if ($n -lt $buffer.Length) { break }
    } while ($true)

    $raw = [System.Text.Encoding]::UTF8.GetString($received.ToArray())
    if ([string]::IsNullOrWhiteSpace($raw)) { throw 'Empty response from aegis_control' }
    $response = $raw | ConvertFrom-Json
    $response | ConvertTo-Json -Depth 20
    if (-not $response.ok) { throw "rules.reload failed: $raw" }
} finally {
    $pipe.Dispose()
}
