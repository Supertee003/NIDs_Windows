[CmdletBinding()]
param(
    [string]$Repo = 'D:\NIDs_Windows'
)

$ErrorActionPreference = 'Continue'
$logDir = Join-Path $Repo '.analysis'
New-Item -ItemType Directory -Force $logDir | Out-Null
$summary = Join-Path $logDir 'native-verification-summary.txt'
$zigLog = Join-Path $logDir 'native-zig-test.log'
$goLog = Join-Path $logDir 'native-go-test.log'

@(
    "started=$(Get-Date -Format o)"
    "repo=$Repo"
) | Set-Content -Encoding UTF8 $summary

function Run-Step([string]$Name, [string]$WorkingDirectory, [string]$FilePath, [string[]]$ArgumentList, [string]$OutputFile) {
    Add-Content $summary "step=$Name start=$(Get-Date -Format o)"
    try {
        $p = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WorkingDirectory $WorkingDirectory -RedirectStandardOutput $OutputFile -RedirectStandardError ($OutputFile + '.err') -Wait -PassThru -WindowStyle Hidden
        Add-Content $summary "step=$Name exit=$($p.ExitCode) end=$(Get-Date -Format o)"
        return $p.ExitCode
    } catch {
        Add-Content $summary "step=$Name exception=$($_.Exception.Message) end=$(Get-Date -Format o)"
        return 999
    }
}

$zig = Run-Step 'zig_build_test' $Repo 'zig.exe' @('build', 'test') $zigLog
$go = Run-Step 'go_test' (Join-Path $Repo 'nose') 'go.exe' @('test', './...', '-timeout', '30s') $goLog

Add-Content $summary "zig_exit=$zig"
Add-Content $summary "go_exit=$go"
Add-Content $summary "finished=$(Get-Date -Format o)"
exit $(if ($zig -eq 0 -and $go -eq 0) { 0 } else { 1 })
