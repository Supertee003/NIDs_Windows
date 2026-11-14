# E5-CLEAN-HOST-001 -- one runbook for the remaining install/boot gate.
#
# RC-FINAL section 3 item 5, INSTALLER-BOOT-MODEL-001 and PREFLIGHT-001 all point
# at the same unproven claim: "a fresh machine installs, reboots, and comes up
# with the boot model". That cannot be proven from the development host, so this
# script exists to make the proof a two-command operation instead of a checklist:
#
#   elevated, before the reboot:
#       powershell -ExecutionPolicy Bypass -File scripts\e5-clean-host.ps1 -Stage Install
#
#   after the machine reboots, from the repo:
#       powershell -ExecutionPolicy Bypass -File scripts\e5-clean-host.ps1 -Stage Verify
#
# `-Stage Verify` writes two artifacts into the evidence directory:
#   preflight-<ts>.json   -- 12 boot-model checks (tools/host_preflight.py)
#   soak-24h-<ts>.json    -- a 24 h window anchored on a counter snapshot
#                            (tools/host_soak_check.py --baseline auto)
#
# `-DryRun` prints every external command and changes nothing, so the plan can be
# reviewed on a host that must not be reinstalled.
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Verify')]
    [string]$Stage = 'Verify',
    [string]$InstallerPath = '',
    [string]$ExpectedInstallerSha256 = '',
    [int]$LossBudget = 3500,
    [double]$MinUptimeMin = 5,
    [string]$ArtifactDir = '',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

if (-not $ArtifactDir) {
    $ArtifactDir = Join-Path $root "admin-evidence\e5-clean-host-$stamp"
}

function Write-Step([string]$text) { Write-Host "[e5] $text" }

function Invoke-External {
    param([string]$Exe, [string[]]$Arguments)
    $shown = "$Exe $($Arguments -join ' ')"
    if ($DryRun) { Write-Step "DRY-RUN: $shown"; return 0 }
    & $Exe @Arguments
    return $LASTEXITCODE
}

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "this stage must run elevated (the installer and the SCM need it)"
    }
}

switch ($Stage) {
    'Install' {
        Write-Step "stage: Install (installer -> boot model -> reboot)"
        if (-not $DryRun) { Assert-Elevated }

        if (-not $InstallerPath) {
            $candidates = @(
                (Join-Path $root 'dist\aegis-installer-5.0.0.exe'),
                (Join-Path $root '.work\aegis-installer-5.0.0.exe')
            )
            $InstallerPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
        }
        if (-not $InstallerPath -or -not (Test-Path $InstallerPath)) {
            throw "installer not found: build it with tools/installer.py --package, or pass -InstallerPath"
        }
        $hash = (Get-FileHash -Algorithm SHA256 -Path $InstallerPath).Hash
        Write-Step "installer: $InstallerPath"
        Write-Step "sha256   : $hash"
        if ($ExpectedInstallerSha256 -and $hash -ne $ExpectedInstallerSha256.ToUpper()) {
            throw "installer hash $hash does not match the expected $ExpectedInstallerSha256"
        }

        # NSIS silent install. The installer aborts setup itself if
        # install-boot-task.ps1 fails, so a 0 here already means the task and
        # AEGIS_LOSS_BUDGET were written.
        $code = Invoke-External -Exe $InstallerPath -Arguments @('/S')
        if ($code -ne 0) { throw "installer exited $code" }
        if ($DryRun) { Write-Step 'install: SKIPPED (dry run)' } else { Write-Step 'install finished' }

        New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
        @{
            stage           = 'install'
            installer       = $InstallerPath
            installer_sha256 = $hash
            expected_sha256 = $ExpectedInstallerSha256
            finished_at     = (Get-Date).ToString('s')
            dry_run         = [bool]$DryRun
        } | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $ArtifactDir 'install.json')

        if ($DryRun) {
            Write-Step 'DRY-RUN: would reboot now (Restart-Computer -Force)'
        } else {
            Write-Step 'rebooting in 10 s; after the machine is back run:'
            Write-Step "  scripts\e5-clean-host.ps1 -Stage Verify -ArtifactDir `"$ArtifactDir`""
            Start-Sleep -Seconds 10
            Restart-Computer -Force
        }
    }

    'Verify' {
        Write-Step "stage: Verify (boot model -> 24 h window anchor)"
        if (-not $DryRun) { Assert-Elevated }
        New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null

        $python = 'python'
        $preflight = Join-Path $root 'tools\host_preflight.py'
        $soak = Join-Path $root 'tools\host_soak_check.py'
        $preflightJson = Join-Path $ArtifactDir "preflight-$stamp.json"
        $soakJson = Join-Path $ArtifactDir "soak-24h-$stamp.json"

        $code = Invoke-External -Exe $python -Arguments @(
            $preflight, '--loss-budget', "$LossBudget",
            '--min-uptime-min', "$MinUptimeMin",
            '--json', $preflightJson
        )
        $preflightFailed = $code -ne 0
        if ($DryRun) {
            # Never print PASS for a check that did not run: a dry run proves the
            # plan, not the host.
            Write-Step 'preflight: SKIPPED (dry run)'
        } else {
            Write-Step ("preflight: " + $(if ($preflightFailed) { 'FAIL' } else { 'PASS' }))
        }

        # Always anchor the soak, even when preflight failed: the window is a
        # clock, and a failed boot model is more reason to keep measuring.
        $null = Invoke-External -Exe $python -Arguments @(
            $soak, '--start', 'auto', '--baseline', 'auto',
            '--hours', '24', '--loss-budget', "$LossBudget",
            '--shed-budget', '4000', '--json', $soakJson
        )
        Write-Step "soak anchor: $soakJson"

        if ($preflightFailed) {
            Write-Step 'RESULT: FAIL -- the boot model is not proven on this host; see the preflight artifact'
            exit 3
        }
        if ($DryRun) {
            Write-Step 'RESULT: DRY-RUN -- plan printed; no check ran and no window started'
            exit 0
        }
        Write-Step 'RESULT: PASS -- 24 h window started; re-run host_soak_check.py to evaluate it'
        exit 0
    }
}
