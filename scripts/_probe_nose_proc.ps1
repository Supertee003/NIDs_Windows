# E5 probe: how is aegis-nose.exe launched? (read-only)
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Get-CimInstance Win32_Process -Filter "Name='aegis-nose.exe'" |
    Select-Object ProcessId, ParentProcessId, CommandLine | Format-List

$p = Get-CimInstance Win32_Process -Filter "Name='aegis-nose.exe'" | Select-Object -First 1
if ($p) {
    Write-Host "`n=== parent process ==="
    Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" |
        Select-Object ProcessId, Name, CommandLine | Format-List
} else {
    Write-Host "no aegis-nose.exe running"
}
