# E5 rollback: restore the working daemon and bring AegisNids back up.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$evDir = Join-Path (Join-Path $repo 'admin-evidence') 'e5-host-proof-20261026'
$runtime = 'C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe'
$bak = Join-Path $evDir 'aegis_nids_old_e19c76c3.exe'
Start-Transcript -Path (Join-Path $evDir 'e5c-rollback.log') -Force
if (-not (Test-Path $bak)) { throw 'backup not found' }
sc.exe stop AegisNids | Out-Host
Start-Sleep -Seconds 2
Copy-Item $bak $runtime -Force
if ((Get-FileHash $runtime -Algorithm SHA256).Hash.ToUpperInvariant() -ne
    'E19C76C3EA493B6FCF4DB840F061DA1563A64791213797C8891C6A7C52B9D770') {
    throw 'restored exe hash mismatch'
}
Write-Host 'old daemon restored (e19c76c3)'
sc.exe start AegisNids | Out-Host
Start-Sleep -Seconds 10
sc.exe query AegisNids | Out-Host
Stop-Transcript
