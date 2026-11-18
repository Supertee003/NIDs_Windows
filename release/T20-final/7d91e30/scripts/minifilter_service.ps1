# AEGIS Minifilter Driver - Service Lifecycle (filter communication port)
# Install / start / stop / status / uninstall for aegis_minifilter.sys with
# rollback of every partial install step.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\minifilter_service.ps1 install     (elevated)
#   powershell -ExecutionPolicy Bypass -File scripts\minifilter_service.ps1 start       (elevated)
#   powershell -ExecutionPolicy Bypass -File scripts\minifilter_service.ps1 status      (any)
#   powershell -ExecutionPolicy Bypass -File scripts\minifilter_service.ps1 stop        (elevated)
#   powershell -ExecutionPolicy Bypass -File scripts\minifilter_service.ps1 uninstall   (elevated)
#
# Service contract (matches drivers/minifilter + capture/minifilter_reader.zig):
#   Name:      AegisMinifilter        Type: filesys   Start: demand
#   Binary:    System32\drivers\aegis_minifilter.sys
#   Port:      \AegisMinifilterPort  (FilterConnectCommunicationPort)
#   Altitude:  370000 (registered BOTH as the service-key Altitude value and
#              the standard Instances\DefaultInstance shape; the filter
#              manager reads what it needs, duplicates are inert)
#
# The DefaultInstance registration is what makes FLTMGR auto-attach the
# filter to every mounted volume - without it the driver loads but no
# callback ever fires.

param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet('install', 'start', 'stop', 'status', 'uninstall')]
    [string]$Action,
    [string]$SysPath = ""
)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Info($msg) { Write-Host "[service] $msg" }
function Warn($msg) { Write-Host "[service] WARN: $msg" -ForegroundColor Yellow }
function Fail($msg) { Write-Host "[service] FAIL: $msg" -ForegroundColor Red; exit 1 }

$SvcName  = 'AegisMinifilter'
$SvcFile  = "$env:SystemRoot\System32\drivers\aegis_minifilter.sys"
$SvcKey   = "HKLM:\SYSTEM\CurrentControlSet\Services\$SvcName"
$Altitude = '370000'
$Instance = 'AegisMinifilter Instance'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $SysPath) { $SysPath = Join-Path $repoRoot "build\x64\minifilter\aegis_minifilter.sys" }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Test-FilterLoaded {
    $f = & fltmc filters 2>$null | Select-String -Pattern "^\s*$SvcName\b"
    return [bool]$f
}

function Show-Status {
    Info "sc query $SvcName :"
    & sc.exe query $SvcName 2>&1 | ForEach-Object { Write-Host "  $_" }
    Write-Host ""
    Info "fltmc filters (Aegis lines):"
    $flt = & fltmc filters 2>&1 | Select-String -Pattern "Aegis|^Filter"
    if ($flt) { $flt | ForEach-Object { Write-Host "  $_" } } else { Write-Host "  (filter not loaded)" }
    Write-Host ""
    Info "fltmc instances (Aegis lines):"
    $inst = & fltmc instances 2>&1 | Select-String -Pattern "Aegis|^Filter"
    if ($inst) { $inst | ForEach-Object { Write-Host "  $_" } } else { Write-Host "  (no instances)" }
}

switch ($Action) {
    'status' {
        Show-Status
        exit 0
    }

    'install' {
        if (-not $isAdmin) { Fail "install requires an elevated shell." }
        if (-not (Test-Path $SysPath)) { Fail "Driver binary not found: $SysPath (run scripts\wdk_build_minifilter.ps1)." }

        $sig = Get-AuthenticodeSignature $SysPath
        Info "Binary signature: $($sig.Status) ($($sig.SignerCertificate.Subject))"
        if ($sig.Status -ne 'Valid') {
            Warn "Binary signature is '$($sig.Status)'. Kernel load needs testsigning + machine-trusted cert (see minifilter_sign.ps1)."
        }

        Info "Copying to $SvcFile ..."
        Copy-Item $SysPath $SvcFile -Force
        if (-not (Test-Path $SvcFile)) { Fail "Copy failed." }

        # Service create (delete a stale one first; sc delete of a missing service is a no-op).
        Info "sc create $SvcName ..."
        & sc.exe create $SvcName type= filesys start= demand binPath= "$SvcFile" DisplayName= "AEGIS NIDS Minifilter Driver" | ForEach-Object { Write-Host "  $_" }
        if ($LASTEXITCODE -ne 0) {
            & sc.exe delete $SvcName | Out-Null
            & sc.exe create $SvcName type= filesys start= demand binPath= "$SvcFile" DisplayName= "AEGIS NIDS Minifilter Driver" | ForEach-Object { Write-Host "  $_" }
            if ($LASTEXITCODE -ne 0) { Fail "sc create failed - rolling back not possible; no service registered." }
        }

        # Altitude registration: BOTH the service-key value form and the
        # standard Instances\DefaultInstance form. Either may be consumed by
        # FLTMGR depending on load path (fltmc load vs sc start); both are
        # correct, duplicates are inert.
        #
        # EVT-230 INCIDENT (2026-10-17): this section once opened with
        # `New-Item -Path $SvcKey -Force`. PowerShell's registry provider
        # DELETES AND RECREATES the key for -Force on an existing key, so
        # every SCM value `sc create` had just written (Type/Start/ImagePath/
        # DisplayName) was wiped a second later. The service then could not
        # start - fltmc load / sc start: 1243 "The specified service does not
        # exist", sc qc: ERROR_FILE_NOT_FOUND - while sc query still printed
        # a Type from the SCM's stale record. NEVER -Force the service key.
        # The -Force uses below are ONLY on the Instances subtree, which is
        # entirely ours to (re)write on every install.
        Info "Registering altitude $Altitude (service key + Instances\DefaultInstance) ..."
        if (-not (Test-Path $SvcKey)) { Fail "Service key vanished after sc create - refusing to continue." }
        New-ItemProperty -Path $SvcKey -Name 'Altitude' -PropertyType String -Value $Altitude -Force | Out-Null
        $instKey = Join-Path $SvcKey 'Instances'
        New-Item -Path $instKey -Force | Out-Null
        New-ItemProperty -Path $instKey -Name 'DefaultInstance' -PropertyType String -Value $Instance -Force | Out-Null
        $instSubKey = Join-Path $instKey $Instance
        New-Item -Path $instSubKey -Force | Out-Null
        New-ItemProperty -Path $instSubKey -Name 'Altitude' -PropertyType String -Value $Altitude -Force | Out-Null
        New-ItemProperty -Path $instSubKey -Name 'Flags' -PropertyType DWord -Value 0 -Force | Out-Null

        # Post-condition guard: the SCM service config must remain intact.
        # A broken install must FAIL here, never report success and then die
        # with an opaque 1243 at load time.
        $vals = (Get-Item $SvcKey).GetValueNames()
        foreach ($need in @('ImagePath', 'Type', 'Start')) {
            if ($vals -notcontains $need) {
                Fail "POST-CONDITION FAILED: service key lost SCM value '$need'. Remedy: sc.exe delete $SvcName then re-run install."
            }
        }

        Info "Install complete. Next: powershell -ExecutionPolicy Bypass -File scripts\minifilter_service.ps1 start"
        exit 0
    }

    'start' {
        if (-not $isAdmin) { Fail "start requires an elevated shell." }
        if (-not (Test-Path $SvcKey)) { Fail "Service not installed (run install first)." }

        Info "fltmc load $SvcName ..."
        & fltmc load $SvcName 2>&1 | ForEach-Object { Write-Host "  $_" }
        Start-Sleep -Milliseconds 800

        if (-not (Test-FilterLoaded)) {
            Warn "fltmc load did not show the filter - trying sc start fallback..."
            & sc.exe start $SvcName 2>&1 | ForEach-Object { Write-Host "  $_" }
            Start-Sleep -Seconds 1
        }

        if (-not (Test-FilterLoaded)) {
            Show-Status
            Fail "Filter is not loaded. Check signature trust (minifilter_sign.ps1), then re-run 'start'."
        }
        Info "Filter loaded."
        Show-Status
        Info "If 'fltmc instances' shows no Aegis lines, the DefaultInstance auto-attach did not happen - report this output."
        exit 0
    }

    'stop' {
        if (-not $isAdmin) { Fail "stop requires an elevated shell." }
        Info "fltmc unload $SvcName ..."
        & fltmc unload $SvcName 2>&1 | ForEach-Object { Write-Host "  $_" }
        if (Test-FilterLoaded) {
            Warn "Still loaded after fltmc unload - trying sc stop..."
            & sc.exe stop $SvcName 2>&1 | ForEach-Object { Write-Host "  $_" }
        }
        Start-Sleep -Seconds 1
        if (Test-FilterLoaded) { Warn "Filter still reported loaded - re-check with status." } else { Info "Filter unloaded." }
        exit 0
    }

    'uninstall' {
        if (-not $isAdmin) { Fail "uninstall requires an elevated shell." }
        Info "Stopping + removing service and files (rollback-safe)..."
        & fltmc unload $SvcName 2>$null | Out-Null
        & sc.exe stop $SvcName 2>$null | Out-Null
        Start-Sleep -Seconds 1
        & sc.exe delete $SvcName 2>&1 | ForEach-Object { Write-Host "  $_" }
        if (Test-Path $SvcFile) { Remove-Item $SvcFile -Force -ErrorAction SilentlyContinue }
        if (Test-Path $SvcKey)  { Remove-Item $SvcKey -Recurse -Force -ErrorAction SilentlyContinue }
        Info "Uninstalled (service, driver copy, altitude keys)."
        exit 0
    }
}
