[CmdletBinding()]
param(
    [string]$ProofRoot = (Join-Path $env:TEMP 'AEGIS-FIM-PROOF'),
    [int]$WaitSeconds = 5
)

$ErrorActionPreference = 'Stop'

Write-Host '[AEGIS ETW PROBE] observe-only benign runtime validation'
Write-Host "[AEGIS ETW PROBE] proof root: $ProofRoot"

New-Item -ItemType Directory -Force -Path $ProofRoot | Out-Null
$marker = 'AEGIS_ETW_PROOF_' + [Guid]::NewGuid().ToString('N')

# ProcessCreate fixture: a short-lived child with a deterministic command line.
$child = Start-Process `
    -FilePath "$env:WINDIR\System32\cmd.exe" `
    -ArgumentList "/d /c echo $marker" `
    -PassThru `
    -WindowStyle Hidden
$child.WaitForExit()
Write-Host "[AEGIS ETW PROBE] process fixture complete: pid=$($child.Id) marker=$marker"

# FIM/file fixture: create, modify, and remove one file only below the proof root.
$file = Join-Path $ProofRoot 'etw-fim-proof.txt'
try {
    Set-Content -LiteralPath $file -Value "$marker CREATE" -Encoding UTF8
    Add-Content -LiteralPath $file -Value "$marker MODIFY" -Encoding UTF8
    Write-Host "[AEGIS ETW PROBE] file fixture complete: $file"
    Start-Sleep -Seconds $WaitSeconds
}
finally {
    if (Test-Path -LiteralPath $file) {
        Remove-Item -LiteralPath $file -Force
        Write-Host "[AEGIS ETW PROBE] cleanup complete: $file"
    }
}

Write-Host '[AEGIS ETW PROBE] expected evidence:'
Write-Host '  PROCESS_CREATE with ImageName, CommandLine, ParentId'
Write-Host '  FILE_CREATE/FILE_MODIFY with FileName under proof root'
Write-Host '[AEGIS ETW PROBE] no enforcement or attack traffic was generated'
