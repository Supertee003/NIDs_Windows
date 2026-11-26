# Dump Application event log WER records (Id 1000) for aegis_nids.exe.
$ErrorActionPreference = 'Stop'
$ev = Get-WinEvent -FilterHashtable @{ LogName='Application'; Id=1000 } -MaxEvents 40 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'aegis_nids' }
$out = @()
foreach ($e in $ev) {
    $p = $e.Properties
    $out += [pscustomobject]@{
        Time              = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        App               = $p[0].Value
        Version           = $p[1].Value
        Timestamp         = $p[2].Value
        FaultingModule    = $p[3].Value
        ModuleVersion     = $p[4].Value
        ModuleTimestamp   = $p[5].Value
        ExceptionCodeHex  = [string]$p[6].Value
        FaultingOffsetHex = [string]$p[7].Value
        ProcessId         = $p[9].Value
        ReportPath        = $p[11].Value
    }
}
$out | ConvertTo-Json -Depth 3 | Set-Content -Encoding UTF8 -Path 'admin-evidence\e5-host-proof-20261026\e5c-eventlog-faults.json'
$out | Format-Table -AutoSize | Out-Host
