$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $root 'analysis/native-validation'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$summary = New-Object System.Collections.Generic.List[string]

function Run-Step([string]$name, [scriptblock]$step) {
    $log = Join-Path $logDir "$name.log"
    "[$(Get-Date -Format o)] START $name" | Set-Content -Encoding UTF8 $log
    & $step *>> $log
    $code = $LASTEXITCODE
    "[$(Get-Date -Format o)] EXIT $code" | Add-Content -Encoding UTF8 $log
    $summary.Add("$name=$code")
}

Set-Location $root
$zigTouched = @(
    'src/core/rust_pep.zig',
    'src/platform/win32_pipe.zig',
    'src/policy/policy_ir.zig',
    'src/policy/pep_bindings.zig',
    'src/policy/action_dispatcher.zig',
    'src/policy/enforcement_receipt.zig',
    'src/control/handler_registry.zig',
    'src/daemon.zig',
    'src/tests/integration/rust_pep_integration.zig'
)
Run-Step 'zig-fmt-touched-check' { zig fmt --check $zigTouched }
Run-Step 'zig-build-test' { zig build test }
Run-Step 'cargo-test' { cargo test --manifest-path Cargo.toml }
Run-Step 'go-test' { Push-Location nose; go test ./...; Pop-Location }

$summary | Set-Content -Encoding UTF8 (Join-Path $logDir 'summary.txt')
$summary | ForEach-Object { Write-Output $_ }
if ($summary | Where-Object { $_ -notmatch '=0$' }) { exit 1 }
exit 0
