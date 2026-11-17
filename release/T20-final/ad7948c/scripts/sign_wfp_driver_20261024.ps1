# Test-sign a pinned WFP driver build with the AEGIS CurrentUser test cert.
#
# No PFX is exported and no password is stored: signtool selects the certificate
# directly from the CurrentUser\My store by its pinned SHA-1 thumbprint. The
# unsigned SHA-256 must be supplied by the operator from the build output so a
# stale binary cannot be signed by accident.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File `
#     scripts/sign_wfp_driver_20261024.ps1 `
#     -ExpectedUnsignedSha256 <build-sha256> `
#     [-ExpectedSignerThumbprint <thumbprint>]

param(
    [Parameter(Mandatory = $true)]
    [string]$ExpectedUnsignedSha256,

    [string]$ExpectedSignerThumbprint = "00E92849867308596564D134BB981EF726798E97"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$target = Join-Path $repo "build\x64\wfp\aegis_wfp.sys"

if (-not (Test-Path $target)) { throw "driver not found: $target" }

$unsignedHash = (Get-FileHash $target -Algorithm SHA256).Hash
if ($unsignedHash -ne $ExpectedUnsignedSha256.ToUpperInvariant()) {
    throw "unsigned driver hash mismatch: $unsignedHash != $ExpectedUnsignedSha256"
}

$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object {
        $_.Thumbprint -eq $ExpectedSignerThumbprint -and $_.HasPrivateKey
    } |
    Select-Object -First 1
if (-not $cert) {
    throw "CurrentUser signing certificate not found: $ExpectedSignerThumbprint"
}

$signtool = Get-ChildItem (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin") `
    -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\' } |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "signtool.exe not found under Windows Kits\10\bin" }

# /sha1 selects the pinned certificate from the CurrentUser store; no PFX or
# plaintext password ever touches disk or the signtool command line.
& $signtool.FullName sign /sha1 $cert.Thumbprint /fd SHA256 /v $target 2>&1 |
    ForEach-Object { Write-Host "  $_" }
if ($LASTEXITCODE -ne 0) { throw "signtool failed with exit $LASTEXITCODE" }

$sig = Get-AuthenticodeSignature $target
if ($sig.Status -ne "Valid") {
    throw "signature status is $($sig.Status), not Valid"
}
if ($null -eq $sig.SignerCertificate -or
    $sig.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint) {
    throw "signed by unexpected certificate: $($sig.SignerCertificate.Thumbprint)"
}

$hash = (Get-FileHash $target -Algorithm SHA256).Hash
Write-Host "[sign] unsigned_sha256=$unsignedHash"
Write-Host "[sign] signed_sha256=$hash"
Write-Host "[sign] status=$($sig.Status) signer=$($sig.SignerCertificate.Thumbprint)"
exit 0
