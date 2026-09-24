# AEGIS WFP Driver - Test Signing (P4 / Phase S toolchain)
# Creates a self-signed code-signing certificate, test-signs the
# built aegis_wfp.sys, and (optionally) enables test signing on the
# host. Production releases must be signed with an EV certificate
# attested by Microsoft instead - this script is the DEVELOPMENT path.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\wfp_sign.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\wfp_sign.ps1 -EnableTestSigning

param(
    [switch]$EnableTestSigning,
    [string]$SysPath = "",
    [string]$CertSubject = "CN=AEGIS NIDS Test Signing",
    [string]$PfxPassword = "aegis-test-2026"
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Info($msg) { Write-Host "[sign] $msg" }
function Warn($msg) { Write-Host "[sign] WARN: $msg" -ForegroundColor Yellow }
function Fail($msg) { Write-Host "[sign] FAIL: $msg" -ForegroundColor Red; exit 1 }

# ----------------------------------------------------------------
# 0. Admin requirement
# ----------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Fail "Administrator required (cert store + bcdedit). Re-run from an elevated prompt."
}

# ----------------------------------------------------------------
# 1. Locate signtool (Windows SDK - layout varies by SDK version)
# ----------------------------------------------------------------
# Modern SDK:  bin\<version>\x64\signtool.exe  (e.g. bin\10.0.28000.0\x64)
# Legacy SDK:  bin\x64\signtool.exe            (versionless)
$signtool = $null
$sdkBinRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
if (Test-Path $sdkBinRoot) {
    # 1a. Newest versioned dir first, x64 preferred over x86.
    $vers = Get-ChildItem -Directory $sdkBinRoot -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^10\.0\.\d+' } |
        Sort-Object { [version]$_.Name } -Descending
    foreach ($v in $vers) {
        foreach ($arch in @("x64", "x86")) {
            $p = Join-Path $v.FullName "$arch\signtool.exe"
            if (Test-Path $p) { $signtool = $p; break }
        }
        if ($signtool) { break }
    }
    # 1b. Legacy versionless bin\x64.
    if (-not $signtool) {
        $p = Join-Path $sdkBinRoot "x64\signtool.exe"
        if (Test-Path $p) { $signtool = $p }
    }
    # 1c. Sweep the whole bin tree (any exotic layout).
    if (-not $signtool) {
        $cand = Get-ChildItem -Path $sdkBinRoot -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x(64|86)\\' } |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($cand) { $signtool = $cand.FullName }
    }
}
if (-not $signtool) {
    Fail "signtool.exe not found under $sdkBinRoot. Install the Windows SDK (comes with the WDK)."
}
Info "signtool: $signtool"

# ----------------------------------------------------------------
# 2. Locate the .sys to sign
# ----------------------------------------------------------------
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $SysPath) { $SysPath = Join-Path $repoRoot "build\x64\wfp\aegis_wfp.sys" }
if (-not (Test-Path $SysPath)) {
    Fail "Driver not found: $SysPath (run scripts\wdk_build_production.ps1 first)."
}
Info "Target: $SysPath"

# ----------------------------------------------------------------
# 3. Create / reuse the test code-signing certificate
# ----------------------------------------------------------------
$store = "Cert:\CurrentUser\My"
$cert = Get-ChildItem $store | Where-Object { $_.Subject -eq $CertSubject -and $_.HasPrivateKey } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if ($cert) {
    Info "Reusing existing certificate: $($CertSubject)"
} else {
    Info "Creating self-signed code-signing certificate..."
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $CertSubject `
        -KeyUsage DigitalSignature -KeySpec Signature -KeyLength 2048 `
        -NotAfter (Get-Date).AddYears(3) -CertStoreLocation $store
    Info "Certificate thumbprint: $($cert.Thumbprint)"
}

# Export PFX (signtool consumes files, not stores, most reliably).
$pfxPath = Join-Path $env:TEMP "aegis_test_signing.pfx"
$pwdSec = ConvertTo-SecureString -String $PfxPassword -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pwdSec | Out-Null
Info "PFX exported: $pfxPath"

# ----------------------------------------------------------------
# 4. Sign the driver
# ----------------------------------------------------------------
& $signtool sign /fd SHA256 /f $pfxPath /p $PfxPassword /v "$SysPath" 2>&1 |
    ForEach-Object { Write-Host "  $_" }
if ($LASTEXITCODE -ne 0) { Fail "signtool failed (exit $LASTEXITCODE)." }

# ----------------------------------------------------------------
# 5. Verify signature
# ----------------------------------------------------------------
$sig = Get-AuthenticodeSignature $SysPath
Info "Signature status: $($sig.Status)"
if ($sig.Status -ne 'Valid') {
    Warn "Signature status is not 'Valid' - a test-signed driver shows as"
    Warn "untrusted until the test cert is installed into trusted roots."
    & $signtool sign /fd SHA256 /f $pfxPath /p $PfxPassword /v "$SysPath" 2>&1 | Out-Null
    # Also install the cert into trusted publishers + roots so the
    # kernel accepts the test signature.
    $cerPath = Join-Path $env:TEMP "aegis_test_signing.cer"
    Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
    Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
    Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
    Info "Test certificate installed into LocalMachine Root + TrustedPublisher."
}

# ----------------------------------------------------------------
# 6. Optional: enable test signing (requires reboot)
# ----------------------------------------------------------------
if ($EnableTestSigning) {
    Write-Host ""
    Warn "Enabling test signing (bcdedit /set testsigning on)."
    Warn "Windows will show a 'Test Mode' watermark and requires a REBOOT."
    $confirm = Read-Host "Proceed? (y/N)"
    if ($confirm -eq 'y') {
        bcdedit /set testsigning on | ForEach-Object { Write-Host "  $_" }
        Info "Test signing ON - reboot required before the driver will load."
    } else {
        Info "Skipped (not enabled)."
    }
}

Write-Host ""
Info "SIGN OK: $SysPath"
Write-Host "Next step: powershell -ExecutionPolicy Bypass -File scripts\wfp_service.ps1 install"
exit 0
