[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$SkipTests,
    [switch]$SkipTypeScript,
    [switch]$SkipRust,
    [switch]$SkipGo,
    [switch]$SkipZig,
    [switch]$SkipPython
)

# AEGIS Milestone 1–2 evidence collector.
# Safe scope: source/build/tests/contracts only. It does not start services,
# install drivers, change WFP state, open the prevention gate, or mutate traffic.
$ErrorActionPreference = 'Continue'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = Join-Path $repo "evidence\milestone-1-2-$stamp"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$summary = New-Object System.Collections.Generic.List[object]

function Save-Text {
    param([string]$Name, [object]$Value)
    $path = Join-Path $out $Name
    ($Value | Out-String -Width 4096) | Set-Content -LiteralPath $path -Encoding UTF8
    return $path
}

function Run-Step {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$Action
    )
    $safe = ($Name -replace '[^A-Za-z0-9_.-]', '_')
    $log = Join-Path $out "$safe.log"
    $started = Get-Date
    Push-Location $repo
    try {
        & $Action 2>&1 | Tee-Object -FilePath $log
        $code = $LASTEXITCODE
        if ($null -eq $code) { $code = 0 }
    } catch {
        $_ | Tee-Object -FilePath $log -Append | Out-Host
        $code = 1
    } finally {
        Pop-Location
    }
    $summary.Add([pscustomobject]@{
        name = $Name
        exit_code = [int]$code
        started = $started.ToString('o')
        finished = (Get-Date).ToString('o')
        log = $log
    })
    return [int]$code
}

Set-Location $repo
Save-Text 'README.txt' @(
    'AEGIS Milestone 1-2 evidence bundle'
    "Repository: $repo"
    "Started: $(Get-Date -Format o)"
    'Safety: no service start/stop, no driver install, no WFP mutation, prevention gate unchanged.'
    'Run this script from a normal PowerShell first. Administrator is not required for this bundle.'
) | Out-Null

Run-Step '01_repo_root_and_git' {
    Write-Output "PWD=$(Get-Location)"
    Write-Output '--- git status ---'
    git status --short --branch
    Write-Output '--- commit ---'
    git rev-parse HEAD
    git log -1 --date=iso --pretty=fuller
    Write-Output '--- remotes ---'
    git remote -v
    Write-Output '--- tracked files ---'
    git ls-files
} | Out-Null

Run-Step '02_toolchain_versions' {
    $tools = @('git','zig','rustc','cargo','go','python','py','cmake','node','npm','cl','msbuild')
    foreach ($tool in $tools) {
        $cmd = Get-Command $tool -ErrorAction SilentlyContinue
        if ($cmd) {
            Write-Output "--- $tool : $($cmd.Source) ---"
            try { & $tool '--version' 2>&1 } catch { $_ }
        } else {
            Write-Output "--- $tool : NOT FOUND ---"
        }
    }
} | Out-Null

Run-Step '03_source_inventory' {
    $exclude = @('.git','target','build','zig-out','node_modules','__pycache__','.pytest_cache','evidence','release')
    Get-ChildItem -LiteralPath $repo -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $relative = $_.FullName.Substring($repo.Length).TrimStart('\')
            $parts = $relative -split '\\'
            ($parts | Where-Object { $exclude -contains $_ }).Count -eq 0
        } |
        Where-Object { $_.Extension -in @('.zig','.c','.h','.cpp','.cc','.rs','.go','.py','.pyx','.pxd','.ts','.tsx','.js','.bat','.cmd','.ps1','.json','.toml','.yaml','.yml') -or $_.Name -in @('CMakeLists.txt','Dockerfile') } |
        Select-Object @{n='path';e={$_.FullName.Substring($repo.Length+1)}}, Length, LastWriteTimeUtc |
        Sort-Object path | ConvertTo-Csv -NoTypeInformation
} | Out-Null

Run-Step '04_build_all' {
    if ($SkipBuild) { Write-Output 'SKIPPED by -SkipBuild'; return }
    $bat = Join-Path $repo 'scripts\build_all.bat'
    if (-not (Test-Path -LiteralPath $bat)) { Write-Output "MISSING: $bat"; exit 2 }
    & cmd.exe /c $bat
} | Out-Null

Run-Step '05_release_manifest' {
    $tool = Join-Path $repo 'tools\release_engineering.py'
    if (-not (Test-Path -LiteralPath $tool)) { Write-Output "MISSING: $tool"; exit 2 }
    & python $tool --manifest
    & python $tool --verify
} | Out-Null

Run-Step '06_operator_rules_validation' {
    $ctl = Join-Path $repo 'tools\aegisctl.py'
    if (-not (Test-Path -LiteralPath $ctl)) { Write-Output "MISSING: $ctl"; exit 2 }
    & python $ctl rules validate
} | Out-Null

if (-not $SkipTests) {
    if (-not $SkipPython) {
        Run-Step '07_python_contract_runtime_tests' {
            $pytest = Get-Command pytest -ErrorAction SilentlyContinue
            if (-not $pytest) { & python -m pytest -q tests\runtime\test_operator_contracts.py tests\runtime\test_wire.py tests\runtime\test_health.py; return }
            & pytest -q tests\runtime\test_operator_contracts.py tests\runtime\test_wire.py tests\runtime\test_health.py tests\policy_signing tests\pep
        } | Out-Null
    }
    if (-not $SkipZig) {
        Run-Step '08_zig_tests' {
            if (-not (Get-Command zig -ErrorAction SilentlyContinue)) { Write-Output 'SKIPPED: zig not found'; return }
            if (-not (Test-Path -LiteralPath (Join-Path $repo 'build.zig'))) { Write-Output 'SKIPPED: build.zig not found'; return }
            & zig build test
        } | Out-Null
    }
    if (-not $SkipGo) {
        Run-Step '09_go_tests' {
            if (-not (Get-Command go -ErrorAction SilentlyContinue)) { Write-Output 'SKIPPED: go not found'; return }
            $mods = Get-ChildItem -LiteralPath $repo -Recurse -Filter go.mod -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\\(target|build|zig-out|node_modules)\\' }
            if (-not $mods) { Write-Output 'SKIPPED: no go.mod found'; return }
            foreach ($mod in $mods) { Push-Location $mod.DirectoryName; try { Write-Output "=== $($mod.FullName) ==="; & go test ./... } finally { Pop-Location } }
        } | Out-Null
    }
    if (-not $SkipRust) {
        Run-Step '10_rust_tests' {
            if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { Write-Output 'SKIPPED: cargo not found'; return }
            $manifests = Get-ChildItem -LiteralPath $repo -Recurse -Filter Cargo.toml -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\\(target|build|zig-out|node_modules)\\' }
            if (-not $manifests) { Write-Output 'SKIPPED: no Cargo.toml found'; return }
            foreach ($manifest in $manifests) { Push-Location $manifest.DirectoryName; try { Write-Output "=== $($manifest.FullName) ==="; & cargo test --workspace } finally { Pop-Location } }
        } | Out-Null
    }
    if (-not $SkipTypeScript) {
        Run-Step '11_typescript_tests' {
            $pkg = Join-Path $repo 'ts_policy\package.json'
            if (-not (Test-Path -LiteralPath $pkg)) { Write-Output 'SKIPPED: ts_policy/package.json not found'; return }
            if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { Write-Output 'SKIPPED: npm not found'; return }
            Push-Location (Split-Path $pkg)
            try { & npm test } finally { Pop-Location }
        } | Out-Null
    }
}

Run-Step '12_artifact_hashes' {
    $artifactRoots = @('build','zig-out','target','nose','release')
    foreach ($rootName in $artifactRoots) {
        $rootPath = Join-Path $repo $rootName
        if (Test-Path -LiteralPath $rootPath) {
            Get-ChildItem -LiteralPath $rootPath -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in @('.exe','.dll','.sys','.pyd','.so','.a','.lib','.json') } |
                ForEach-Object {
                    try { Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 | Select-Object Hash, Path } catch { Write-Output $_ }
                }
        }
    }
} | Out-Null

$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'summary.json') -Encoding UTF8
Compress-Archive -Path (Join-Path $out '*') -DestinationPath (Join-Path $out '..\milestone-1-2-evidence.zip') -Force
Write-Output "EVIDENCE_DIR=$out"
Write-Output "EVIDENCE_ZIP=$(Join-Path $out '..\milestone-1-2-evidence.zip')"
Write-Output 'Complete. Review summary.json and logs before sharing.'
