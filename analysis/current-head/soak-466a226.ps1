#Requires -RunAsAdministrator
# 24 h soak window for candidate 466a226 (RB-024). All paths are absolute and
# derived from this script, so the caller's directory cannot select the wrong
# tree. Run from ANYwhere in an ELEVATED PowerShell:
#
#   START  (once, then do NOT touch the host):
#     powershell -NoProfile -ExecutionPolicy Bypass -File "...\soak-466a226.ps1" -Mode start
#   HOURLY (optional, same baseline):
#     powershell -NoProfile -ExecutionPolicy Bypass -File "...\soak-466a226.ps1" -Mode check
#   FINAL  (after a real 24 h):
#     powershell -NoProfile -ExecutionPolicy Bypass -File "...\soak-466a226.ps1" -Mode final

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('start', 'check', 'final')]
    [string]$Mode
)

$ErrorActionPreference = 'Stop'

$Repo     = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $Repo
$Evidence = Join-Path $Repo 'admin-evidence\e5-clean-host-20261120-final'
$Baseline = Join-Path $Evidence 'soak-24h.baseline.json'
$Preflight = Join-Path $Evidence 'preflight-20261120.json'

if (-not (Test-Path -LiteralPath $Preflight)) {
    throw "Missing E5 preflight: $Preflight - run apply-466a226-and-preflight.ps1 first"
}
if ($Mode -ne 'start' -and -not (Test-Path -LiteralPath $Baseline)) {
    throw "Missing soak baseline: $Baseline - run -Mode start first"
}
New-Item -ItemType Directory -Path $Evidence -Force | Out-Null

$name = switch ($Mode) {
    'start' { 'soak-24h-delta-start.json' }
    'check' { 'soak-24h-delta-latest.json' }
    'final' { 'soak-24h-delta-final.json' }
}
$out = Join-Path $Evidence $name

$pyArgs = @(
    'tools\host_soak_check.py',
    '--start', 'auto',
    '--hours', '24',
    '--loss-budget', '3500',
    '--shed-budget', '20000'
)
if ($Mode -eq 'start') {
    $pyArgs += @('--baseline', 'auto', '--baseline-out', $Baseline)
} else {
    $pyArgs += @('--baseline', $Baseline)
}
$pyArgs += @('--json', $out)

Write-Host "== soak $Mode | repo=$Repo =="
python @pyArgs
$exit = $LASTEXITCODE

if (Test-Path -LiteralPath $out) {
    $r = Get-Content -LiteralPath $out -Raw -Encoding UTF8 | ConvertFrom-Json
    "verdict:       $($r.verdict)"
    "elapsed_hours: $($r.elapsed_hours) / $($r.required_hours)"
    if ($r.problems) { "problems:      $($r.problems -join '; ')" }
    if ($r.verdict -eq 'FAIL') {
        throw "Soak is FAIL - do not publish. Paste this output to the agent."
    }
} else {
    throw "Soak produced no artifact at $out"
}

if ($Mode -eq 'final' -and $r.verdict -eq 'PASS') {
    Write-Host "== 24 h SOAK PASS =="
    Write-Host "Close the board from the worktree with the trust anchor:"
    Write-Host '  $env:AEGIS_RELEASE_TRUSTED_PUBLIC_KEY = ''txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o='''
    Write-Host '  python tools\final_audit.py --release-check'
    Write-Host "Then tell the agent; it will rebase records and verify. No tag/push/publish before that."
}
if ($exit -ne 0) { Write-Host "note: host_soak_check exit=$exit" }
