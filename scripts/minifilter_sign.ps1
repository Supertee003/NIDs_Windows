# AEGIS Minifilter Driver - Test Signing
# Test-signs build\x64\minifilter\aegis_minifilter.sys with a trusted-on-host
# code-signing certificate. Kernel load requires (a) testsigning enabled
# (bcdedit /set testsigning on) and (b) the signing cert chaining to a
# certificate in the LOCAL MACHINE trusted root store.
#
# This script signs without elevation when the certificate (with private
# key) already exists in Cert:\CurrentUser\My and is already trusted in
# the machine root store - the state of this lab host ("AEGIS Test
# Signer"). Elevated only needed to import trust for a NEW certificate.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\minifilter_sign.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\minifilter_sign.ps1 -CertSubject "CN=AEGIS NIDS Test Signing"
#   powershell -ExecutionPolicy Bypass -File scripts\minifilter_sign.ps1 -TrustCertToMachine   (elevated)

param(
    [string]$SysPath = "",
    [string]$CertCN = "AEGIS Test Signer",
    [string]$PfxPassword = "aegis-test-2026",
    [switch]$TrustCertToMachine
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Info($msg) { Write-Host "[sign] $msg" }
function Warn($msg) { Write-Host "[sign] WARN: $msg" -ForegroundColor Yellow }
function Fail($msg) { Write-Host "[sign] FAIL: $msg" -ForegroundColor Red; exit 1 }

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $SysPath) { $SysPath = Join-Path $repoRoot "build\x64\minifilter\aegis_minifilter.sys" }

# ----------------------------------------------------------------
# 1. Locate signtool (Windows SDK)
# ----------------------------------------------------------------
$kitsBin = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
$signtool = Get-ChildItem -Path $kitsBin -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $signtool) {
    Fail "signtool.exe not found under $kitsBin (install the Windows SDK signing tools)."
}
Info "signtool: $signtool"

# ----------------------------------------------------------------
# 2. Target must exist
# ----------------------------------------------------------------
if (-not (Test-Path $SysPath)) {
    Fail "Target .sys not found: $SysPath (run scripts\wdk_build_minifilter.ps1 first)."
}
Info "Target:   $SysPath"

# ----------------------------------------------------------------
# 3. Find or create the code-signing certificate
# ----------------------------------------------------------------
# Subject match is by CN substring: the host's WFP-trusted signer is
# "CN=AEGIS Test Signer, O=AEGIS NIDS, C=TH" and an exact-string match
# would miss it (and then create an untrusted duplicate). Candidates
# already trusted in the machine root store win; newest expiry breaks ties.
$candidates = @(
    Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue
    Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue
) | Where-Object { $_.Subject -like "*CN=$CertCN*" -and $_.HasPrivateKey }
$trustedThumbs = @(
    Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Thumbprint
)
$cert = $candidates |
    Sort-Object @{ Expression = { if ($trustedThumbs -contains $_.Thumbprint) { 0 } else { 1 } } },
                @{ Expression = { $_.NotAfter }; Descending = $true } |
    Select-Object -First 1
if (-not $cert) {
    Info "No '$CertCN' code-signing certificate with private key found - creating self-signed cert..."
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=$CertCN" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddYears(5)
    if (-not $cert) { Fail "Failed to create self-signed certificate." }
    Warn "New certificate created - machine trust import will be REQUIRED before kernel load (re-run with -TrustCertToMachine elevated)."
}
Info "Certificate: $($cert.Subject) [$($cert.Thumbprint)] (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))"

# ----------------------------------------------------------------
# 4. Machine trust state (readable without admin)
# ----------------------------------------------------------------
$trustedRoot = $false
$trustedPub = $false
try {
    $trustedRoot = [bool](Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $cert.Thumbprint })
    $trustedPub = [bool](Get-ChildItem Cert:\LocalMachine\TrustedPublisher -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $cert.Thumbprint })
} catch {
    Warn "Could not read local machine stores: $_"
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($TrustCertToMachine -or (-not $trustedRoot)) {
    if ($isAdmin) {
        $cerPath = Join-Path $env:TEMP "aegis_minifilter_cert.cer"
        Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
        if (-not $trustedRoot) {
            Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
            Info "Imported to LocalMachine\Root."
        }
        if (-not $trustedPub) {
            Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
            Info "Imported to LocalMachine\TrustedPublisher."
        }
        Remove-Item $cerPath -Force -ErrorAction SilentlyContinue
    } else {
        Warn "Certificate is NOT trusted in the machine root store and this shell is not elevated."
        Warn "Kernel load will fail until a trusted copy exists. Export + import elevated:"
        Warn "  `$c = Get-ChildItem Cert:\CurrentUser\My | Where-Object { `$_.Thumbprint -eq '$($cert.Thumbprint)' }"
        Warn "  Export-Certificate -Cert `$c -FilePath `$env:TEMP\aegis_minifilter_cert.cer"
        Warn "  Import-Certificate -FilePath `$env:TEMP\aegis_minifilter_cert.cer -CertStoreLocation Cert:\LocalMachine\Root"
    }
} else {
    Info "Machine root trust: OK (already trusted; no import needed)."
}

# ----------------------------------------------------------------
# 5. Sign (PFX in temp; cleaned up)
# ----------------------------------------------------------------
$pfxPath = Join-Path $env:TEMP "aegis_minifilter_sign.pfx"
$securePwd = ConvertTo-SecureString -String $PfxPassword -Force -AsPlainText
try {
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $securePwd -Force | Out-Null
    Info "Signing $SysPath ..."
    & $signtool sign /fd SHA256 /f $pfxPath /p $PfxPassword $SysPath
    if ($LASTEXITCODE -ne 0) { Fail "signtool sign failed (exit $LASTEXITCODE)." }
} finally {
    Remove-Item $pfxPath -Force -ErrorAction SilentlyContinue
}

# ----------------------------------------------------------------
# 6. Verify signature state
# ----------------------------------------------------------------
$sig = Get-AuthenticodeSignature $SysPath
Info "Signature status: $($sig.Status) ($($sig.SignerCertificate.Subject))"
if ($sig.Status -ne 'Valid') {
    Warn "Signature status is '$($sig.Status)': kernel load may fail until the machine trusts the cert (see above)."
}

$hash = (Get-FileHash $SysPath -Algorithm SHA256).Hash
Info "SHA-256: $hash"
Info "Signed OK: $SysPath"
exit 0
