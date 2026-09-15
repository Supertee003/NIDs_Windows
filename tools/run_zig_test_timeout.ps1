param(
    [string]$Zig = "zig",
    [string]$Source = "src/capture/npcap_adapter.zig",
    [int]$TimeoutSeconds = 15
)

$outLog = Join-Path (Get-Location) "zig-test.stdout.log"
$errLog = Join-Path (Get-Location) "zig-test.stderr.log"
Remove-Item $outLog,$errLog -ErrorAction SilentlyContinue
$args = @("test", $Source, "-target", "x86_64-windows", "-O", "Debug")
$p = Start-Process -FilePath $Zig -ArgumentList $args -RedirectStandardOutput $outLog -RedirectStandardError $errLog -PassThru -WindowStyle Hidden
if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
    Stop-Process -Id $p.Id -Force
    Write-Output "TIMEOUT after $TimeoutSeconds seconds"
    if (Test-Path $outLog) { Get-Content $outLog }
    if (Test-Path $errLog) { Get-Content $errLog }
    exit 124
}
Write-Output "EXIT_CODE=$($p.ExitCode)"
if (Test-Path $outLog) { Get-Content $outLog }
if (Test-Path $errLog) { Get-Content $errLog }
exit $p.ExitCode
