# AEGIS NIDS - install-time boot model and loss budget.
#
# Called by the installer after the AegisNids service exists and before the
# "Start AEGIS Service Now" section. It:
#   1. sets the service Environment AEGIS_LOSS_BUDGET (default 3500);
#   2. enforces AegisNids DEMAND_START (the boot task is the loader);
#   3. registers AegisBootSequence (AtStartup, SYSTEM, 20 s delay) pointing at
#      the installed boot-sequence.ps1.
#
# Idempotent: reinstall reuses the task and replaces the budget value.
# Exits non-zero on failure so the installer can abort instead of shipping a
# stack that will not come back after reboot.

param(
    [int]$LossBudget = 3500
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$boot = Join-Path $PSScriptRoot 'boot-sequence.ps1'
$svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\AegisNids'
$logDir = Join-Path $env:ProgramData 'AEGIS'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$log = Join-Path $logDir 'install-boot-task.log'

function Log([string]$m) {
    $line = "{0}  {1}" -f (Get-Date).ToString('HH:mm:ss'), $m
    Add-Content -Path $log -Value $line -Encoding utf8
}

try {
    if (-not (Test-Path -LiteralPath $boot)) { throw "boot script missing: $boot" }
    if (-not (Test-Path -LiteralPath $svcKey)) { throw "service key missing: $svcKey (installer must create AegisNids first)" }

    # 1. Loss budget in the service environment. Preserve any other values.
    $current = (Get-ItemProperty -Path $svcKey -Name Environment -ErrorAction SilentlyContinue).Environment
    $values = @($current | Where-Object { $_ -and $_ -notmatch '^AEGIS_LOSS_BUDGET=' })
    $values += "AEGIS_LOSS_BUDGET=$LossBudget"
    Set-ItemProperty -Path $svcKey -Name Environment -Value ([string[]]$values) -Type MultiString
    Log ("service Environment: " + ($values -join '; '))

    # 2. The boot task is the only loader; keep the daemon demand-start.
    $out = (& sc.exe config AegisNids start= demand 2>&1 | Out-String)
    if ($out -match 'FAILED|denied') { throw "sc config failed: $($out.Trim())" }
    Log 'AegisNids START_TYPE = DEMAND_START'

    # 3. Register the loader.
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $boot)
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = 'PT20S'
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
    Register-ScheduledTask -TaskName 'AegisBootSequence' -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force | Out-Null
    Log 'registered AegisBootSequence (AtStartup, SYSTEM, 20s delay)'

    $result = [ordered]@{
        checked_at = (Get-Date).ToString('s')
        boot_script = $boot
        loss_budget = $LossBudget
        environment = @($values)
        task = 'AegisBootSequence'
        ok = $true
    }
    $result | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $logDir 'install-boot-task.json') -Encoding utf8
    Log 'install boot model complete'
    exit 0
} catch {
    Log "FAILED: $($_.Exception.Message)"
    $result = [ordered]@{
        checked_at = (Get-Date).ToString('s')
        boot_script = $boot
        loss_budget = $LossBudget
        ok = $false
        reason = $_.Exception.Message
    }
    $result | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $logDir 'install-boot-task.json') -Encoding utf8
    exit 1
}
