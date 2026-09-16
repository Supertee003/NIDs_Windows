[CmdletBinding()]
param(
    [Parameter(Position=0)] [string]$Command = "help",
    [Parameter(Position=1, ValueFromRemainingArguments=$true)] [string[]]$Args
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$cli = Join-Path $root "tools\aegisctl.py"

function Invoke-Cli([string[]]$Arguments) {
    & python $cli @Arguments
    exit $LASTEXITCODE
}

switch ($Command.ToLowerInvariant()) {
    "help" { @"
AEGIS NIDS operator console

Usage:
  .\scripts\aegis.ps1 status
  .\scripts\aegis.ps1 doctor
  .\scripts\aegis.ps1 health
  .\scripts\aegis.ps1 readiness
  .\scripts\aegis.ps1 metrics
  .\scripts\aegis.ps1 snapshot
  .\scripts\aegis.ps1 rules list|validate|reload
  .\scripts\aegis.ps1 events stats|count|tail
  .\scripts\aegis.ps1 forensic verify|list
  .\scripts\aegis.ps1 tui
  .\scripts\aegis.ps1 tui --mode dashboard --interval 5
  .\scripts\aegis.ps1 tui --mode dashboard --once
  .\scripts\aegis.ps1 console --role operator|admin
  .\scripts\aegis.ps1 console --mode snapshot
  .\scripts\aegis.ps1 web
  .\scripts\aegis.ps1 graph
  .\scripts\aegis.ps1 test golden-path
  .\scripts\aegis.ps1 version
  .\scripts\aegis.ps1 start

All operational mutations use the protected Control Center pipe.
"@; exit 0 }
    "status" { Invoke-Cli (@("status") + $Args) }
    "health" { Invoke-Cli (@("health") + $Args) }
    "readiness" { Invoke-Cli (@("readiness") + $Args) }
    "doctor" { Invoke-Cli @("diagnose") }
    "metrics" { Invoke-Cli (@("metrics") + $Args) }
    "snapshot" { Invoke-Cli @("snapshot") }
    "version" { Invoke-Cli @("version") }
    "start" { Invoke-Cli @("start", "--all") }
    "tui" {
        $console = Join-Path $root "scripts\aegis_console.py"
        if (-not (Test-Path $console)) { throw "TUI entrypoint not found: $console" }
        & python $console @Args
        exit $LASTEXITCODE
    }
    "console" {
        $console = Join-Path $root "scripts\aegis_console_pro.py"
        if (-not (Test-Path $console)) { throw "Pro console entrypoint not found: $console" }
        & python $console @Args
        exit $LASTEXITCODE
    }
    "web" {
        $dashboard = Join-Path $root "aegis_dashboard\target\release\aegis_dashboard.exe"
        if (Test-Path $dashboard) {
            Start-Process $dashboard -WorkingDirectory $root
            Write-Host "AEGIS Web/Desktop dashboard started"
            exit 0
        }
        $manifest = Join-Path $root "aegis_dashboard\Cargo.toml"
        if (-not (Test-Path $manifest)) { throw "Dashboard project not found: $manifest" }
        Write-Host "Release dashboard not found; starting Cargo development dashboard..."
        & cargo run --manifest-path $manifest --release
        exit $LASTEXITCODE
    }
    "graph" {
        $graph = Join-Path $root "scripts\aegis_graph.py"
        & python $graph @Args
        exit $LASTEXITCODE
    }
    "rules" {
        if (-not $Args -or $Args.Count -eq 0) { Invoke-Cli @("rules", "list") }
        Invoke-Cli (@("rules") + $Args)
    }
    "events" {
        if (-not $Args -or $Args.Count -eq 0) { Invoke-Cli @("events", "stats") }
        Invoke-Cli (@("events") + $Args)
    }
    "forensic" {
        if (-not $Args -or $Args.Count -eq 0) { Invoke-Cli @("forensics", "verify") }
        if ($Args[0].ToLowerInvariant() -eq "verify") { Invoke-Cli @("forensics", "verify") }
        if ($Args[0].ToLowerInvariant() -eq "list") { Invoke-Cli @("forensics", "list") }
        Invoke-Cli (@("forensic") + $Args)
    }
    "forensics" { Invoke-Cli (@("forensics") + $Args) }
    "test" {
        $testName = if ($Args -and $Args.Count -gt 0) { $Args[0] } else { "golden-path" }
        switch ($testName.ToLowerInvariant()) {
            "golden-path" {
                & python (Join-Path $root "scripts\aegis_event_gen.py") --pipe --fixture xss --count 1
                if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
                Invoke-Cli @("metrics")
            }
            default { Write-Error "Unknown test: $testName. Available: golden-path" }
        }
    }
    default { Write-Error "Unknown command '$Command'. Run .\scripts\aegis.ps1 help" }
}
