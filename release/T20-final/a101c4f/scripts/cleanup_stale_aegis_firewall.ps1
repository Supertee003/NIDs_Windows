<#
.SYNOPSIS
    Dry-run audit of stale AEGIS_BLOCK_10.0.0.99 Windows Firewall rules.

.DESCRIPTION
    Earlier canary runs created one inbound Block rule per attempt (currently
    60 identical rules: Action=Block, Direction=Inbound, RemoteAddress=10.0.0.99,
    Protocol=Any). They are test residue, but ownership is not yet confirmed.
    This script therefore:

      1. exports the whole firewall policy (netsh advfirewall export .wfw)
         and a JSON snapshot of every matching rule;
      2. records before counts and a rollback instruction;
      3. never deletes anything.

    The -Apply switch is intentionally rejected until rule ownership is
    explicitly established. Allow rules (aegis-nids, aegis-dashboard,
    aegis-aggregator) are never touched.

.PARAMETER Apply
    Reserved and rejected; this script is dry-run only.

.PARAMETER EvidenceDir
    Evidence directory; defaults to admin-evidence\firewall-cleanup-<timestamp>.

.NOTES
    Rollback is not needed because nothing is changed. If a future, separately
    authorized cleanup runs, it must retain the exported .wfw snapshot.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [string]$EvidenceDir = ""
)

$ErrorActionPreference = "Stop"
$Target = "AEGIS_BLOCK_10.0.0.99"

if ($Apply) {
    throw "apply is disabled: ownership of $Target rules is not confirmed; dry-run only"
}

$repo = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($EvidenceDir)) {
    $EvidenceDir = Join-Path $repo ("admin-evidence\firewall-cleanup-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
}
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

function Get-TargetRules {
    @(Get-NetFirewallRule -DisplayName $Target -ErrorAction SilentlyContinue)
}

$before = Get-TargetRules
$allBefore = @(Get-NetFirewallRule -ErrorAction SilentlyContinue)
$result = [ordered]@{
    script = "cleanup_stale_aegis_firewall"
    target = $Target
    apply = [bool]$Apply
    elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    before_matching = $before.Count
    before_all = $allBefore.Count
    after_matching = $null
    after_all = $null
    removed = 0
    rollback = "netsh advfirewall import `"$EvidenceDir\firewall-before.wfw`""
}

# Full-policy rollback point. Requires elevation; record the failure instead
# of pretending the operation is reversible.
$wfw = Join-Path $EvidenceDir "firewall-before.wfw"
try {
    netsh advfirewall export "$wfw" 2>&1 | Out-Null
    $result["policy_export"] = (Test-Path $wfw)
} catch {
    $result["policy_export"] = $false
    $result["policy_export_error"] = $_.Exception.Message
}

$beforeJson = Join-Path $EvidenceDir "rules-before.json"
$before | Select-Object Name, DisplayName, Enabled, Direction, Action, Profile, Description |
    ConvertTo-Json -Depth 5 | Set-Content -Path $beforeJson -Encoding UTF8
$result["rules_before_json"] = $beforeJson

Write-Host "DRY_RUN matching=$($before.Count) all=$($allBefore.Count) evidence=$EvidenceDir"
$result["mode"] = "dry-run"
$result | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $EvidenceDir "result.json") -Encoding UTF8
exit 0
