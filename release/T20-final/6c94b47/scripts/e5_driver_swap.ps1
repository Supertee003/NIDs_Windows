# E5-A: swap in the outbound-capable aegis_wfp.sys (commit 767cb98 build).
# Test-signs build\x64\wfp\aegis_wfp.sys, stops AegisWfp, copies the binary,
# restarts the service, and records hashes/status as evidence.
# Must run elevated (sign cert store + service control).
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$evDir = Join-Path (Join-Path $repo 'admin-evidence') 'e5-host-proof-20261026'
New-Item -ItemType Directory -Force -Path $evDir | Out-Null
$log = Join-Path $evDir 'e5a-driver-swap.log'
Start-Transcript -Path $log -Force

Write-Host "=== A1. expected candidate ==="
$src = Join-Path (Join-Path $repo 'build\x64\wfp') 'aegis_wfp.sys'
$srcHash = (Get-FileHash $src -Algorithm SHA256).Hash
$srcLen = (Get-Item $src).Length
Write-Host "candidate: $src"
Write-Host "candidate SHA-256: $srcHash ($srcLen bytes)"
if ($srcHash -ne '7EDE4DCD4DC1D24CC2A98916648258A7B98437C0D8ECD70A0C3144C08D87A7C9') {
    Write-Warning "candidate hash differs from the recorded O2 build!"
    Write-Warning "Aborting swap. Verify scripts\wdk_build_production.ps1 output first."
    Stop-Transcript
    exit 1
}

Write-Host "=== A2. sign (test cert, dev path) ==="
& powershell -ExecutionPolicy Bypass -File (Join-Path (Split-Path -Parent $PSCommandPath) 'wfp_sign.ps1')
if ($LASTEXITCODE -ne 0) { Write-Error "sign failed"; Stop-Transcript; exit 1 }
$sig = Get-AuthenticodeSignature $src
Write-Host "post-sign status: $($sig.Status) (test-signed shows as Untrusted until roots installed; wfp_sign installs roots on warning)"

Write-Host "=== A3. backup installed driver ==="
$svcBin = "$env:SystemRoot\System32\drivers\aegis_wfp.sys"
$bak = Join-Path $evDir 'aegis_wfp_old.sys'
Copy-Item $svcBin $bak -Force
Write-Host "backup: $bak SHA-256: $((Get-FileHash $bak -Algorithm SHA256).Hash)"

Write-Host "=== A4. stop AegisWfp ==="
sc.exe stop AegisWfp | Out-Host
Start-Sleep -Seconds 2
sc.exe query AegisWfp | Out-Host

Write-Host "=== A5. copy new driver + start ==="
Copy-Item $src $svcBin -Force
$installedHash = (Get-FileHash $svcBin -Algorithm SHA256).Hash
Write-Host "installed SHA-256: $installedHash ($((Get-Item $svcBin).Length) bytes)"
sc.exe start AegisWfp | Out-Host
Start-Sleep -Seconds 2
sc.exe query AegisWfp | Out-Host

Write-Host "=== A6. result ==="
if ($installedHash -ne $srcHash) { Write-Error "installed hash mismatch"; Stop-Transcript; exit 1 }
$state = (sc.exe query AegisWfp | Out-String) -match 'RUNNING'
if ($state) {
    Write-Host "E5-A SWAP OK: driver RUNNING with outbound candidate $srcHash"
    Write-Host "rollback available: $bak"
} else {
    Write-Error "E5-A driver not RUNNING after swap; rollback: copy $bak -> $svcBin and sc start AegisWfp"
    Stop-Transcript
    exit 1
}
Stop-Transcript
