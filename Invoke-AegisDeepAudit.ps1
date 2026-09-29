[CmdletBinding()]
param(
    [string]$Repo = 'D:\NIDs_Windows',
    [string]$OutDir = (Join-Path (Get-Location) ('aegis-audit-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [switch]$RunBuilds,
    [switch]$RunTests
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Transcript = Join-Path $OutDir 'audit.log'
Start-Transcript -Path $Transcript -Force | Out-Null

function Section([string]$Name) {
    Write-Host "`n===== $Name =====" -ForegroundColor Cyan
}
function Save([string]$Name, [scriptblock]$Block) {
    $path = Join-Path $OutDir $Name
    & $Block *>&1 | Tee-Object -FilePath $path
}
function Run([string]$Name, [scriptblock]$Block) {
    Section $Name
    $sw = [Diagnostics.Stopwatch]::StartNew()
    & $Block *>&1
    $code = $LASTEXITCODE
    $sw.Stop()
    Write-Host "[exit=$code elapsed=$($sw.Elapsed)]" -ForegroundColor DarkGray
}

if (-not (Test-Path (Join-Path $Repo '.git'))) { throw "Not a git repository: $Repo" }
Set-Location $Repo

Section '1. Source of truth and working tree'
Save '01-git.txt' { git rev-parse HEAD; git branch --show-current; git status --short; git log -1 --oneline; git diff --stat }
$Head = (git rev-parse HEAD).Trim()
Write-Host "HEAD=$Head"

Section '2. Machine-map freshness'
$mapNames = @('SYSTEM_MAP.json','FLOW_MAP.json','AUTHORITY_MAP.json','CONTRACT_MAP.json','EVIDENCE_INDEX.json','build_truth.json','runtime_manifest.json')
$mapRows = foreach ($name in $mapNames) {
    $file = Join-Path $Repo $name
    if (Test-Path $file) {
        try {
            $j = Get-Content $file -Raw | ConvertFrom-Json
            [pscustomobject]@{ file=$name; head_sha=$j.head_sha; match=($j.head_sha -eq $Head); created_at=$j.created_at }
        } catch { [pscustomobject]@{ file=$name; head_sha='JSON_ERROR'; match=$false; created_at='' } }
    } else { [pscustomobject]@{ file=$name; head_sha='MISSING'; match=$false; created_at='' } }
}
$mapRows | Format-Table -AutoSize | Tee-Object (Join-Path $OutDir '02-map-freshness.txt')

Section '3. Complete tracked-file inventory by class/extension'
Save '03-file-inventory.txt' {
    $files = git ls-files
    "TOTAL_TRACKED=$($files.Count)"
    $files | Group-Object { [IO.Path]::GetExtension($_).ToLowerInvariant() } | Sort-Object Count -Descending | Format-Table Name,Count -AutoSize
    ''
    '--- tracked source files ---'
    $files | Where-Object { $_ -match '\.(zig|go|rs|c|h|cpp|hpp|py|pyx|ts|tsx|js|mjs|ps1|bat|cmd)$' }
}

Section '4. Authority and forbidden-edge scan'
$patterns = @(
  'aegis_pep_(enforce|evaluate|unblock|query|provider)',
  'WFP|Fwpm|IOCTL|DeviceIoControl|CreateService|OpenSCManager',
  'BLOCKED_CONFIRMED|ENFORCED|host_effect_confirmed|filter_id',
  'aegis_control|aegis_nose|HEALTH|health\.check',
  'sec_monitor|windows_enforce|shield/src/pep',
  'TODO|FIXME|HACK|mock|stub|placeholder|simulation'
)
foreach ($p in $patterns) {
    $safe = ($p -replace '[^A-Za-z0-9]+','_').Trim('_')
    Save ("04-scan-$safe.txt") { rg -n -S --hidden --glob '!.git/**' --glob '!target/**' --glob '!build/**' --glob '!zig-out/**' --glob '!release/**' $p . }
}

Section '5. Contract/layout inspection'
Save '05-contract-references.txt' {
    rg -n -S 'CanonicalEvent|109.?byte|PepRequest|PepResponse|PepFilterState|EnforcementReceipt|receipt_version|request_id|event_id|policy_id|trace_id|audit_id|host_effect_confirmed|CONTROL_PROTOCOL|HEALTH' src nose rust-src brain shared tests tools docs contracts
}

Section '6. Lifecycle and single-owner inspection'
Save '06-lifecycle-references.txt' {
    rg -n -S 'PID|pid|named pipe|CreateNamedPipe|aegis_control|owner|stale|restart|shutdown|worker|generation|health|ready|required_ready|advisory_ready' src tools tests scripts docs configs
}

Section '7. Static policy/security checks'
Save '07-static-security.txt' {
    if (Test-Path 'analysis/deep_audit/run_p0_static_checks.py') { python analysis/deep_audit/run_p0_static_checks.py }
    if (Test-Path 'tools/inspect_pe_exports.py') { python tools/inspect_pe_exports.py }
    rg -n -S 'allow|deny|fail.closed|fail_closed|bypass|authority|privileged|signature|nonce|replay|quota|freshness' rust-src/src rust-src src/policy tests/security tests/pep 2>$null
}

Section '8. Existing evidence and acceptance claims'
Save '08-evidence-index.txt' {
    python -c "import json; d=json.load(open('EVIDENCE_INDEX.json')); print(json.dumps(d,indent=2))"
}
Save '08-acceptance-claims.txt' {
    rg -n -S 'PASS|FAIL|PRODUCTION|ACCEPT|E[0-6]|host.effect|cleanup|restart|observe.only|WFP|receipt' analysis evidence admin-evidence docs tests 2>$null
}

if ($RunBuilds) {
    Section '9. Native builds (opt-in)'
    Run 'zig-build.txt' { zig build }
    Run 'zig-test-build.txt' { zig build test }
    Run 'rust-build.txt' { cargo build --release }
    Run 'cmake-build.txt' { cmake -B build; cmake --build build --config Release }
    Run 'go-build-test.txt' { Push-Location nose; go test ./...; go build -o aegis-nose.exe .; Pop-Location }
    Run 'typescript-check-test.txt' { Push-Location ts_policy; npm run typecheck; npm run test:all; Pop-Location }
}

if ($RunTests) {
    Section '10. Test suites (opt-in; no host enforcement proof by itself)'
    Run 'pytest-security-contracts-runtime-wfp.txt' { python -m pytest tests/security tests/contracts tests/runtime tests/wfp -q }
    Run 'pytest-all.txt' { python -m pytest -q }
}

Section '11. Summary and next gates'
$summary = @"
Repo: $Repo
HEAD: $Head
Output: $OutDir

Interpretation rules:
- Any map match=false is stale truth and must be regenerated before relying on it.
- A policy action BLOCK is not a host block.
- provider_ready/capable is not host_effect_observed.
- BLOCKED_CONFIRMED requires a valid receipt plus host-effect read-back.
- Static/unit tests are E0-E2; real Windows host proof is E5; production simulation is E6.
- This script is read-only with respect to WFP and does not run attack traffic.

Required next vertical slice after this audit:
1) single runtime owner + stale pipe/PID rejection
2) Brain {op:HEALTH} contract with component/state/version/ready
3) observe-only proof with no enforcement request
4) narrow WFP canary via Rust PEP only
5) filter read-back, host effect, receipt, forensic chain
6) exact-filter cleanup and restart/recovery proof
"@
$summary | Tee-Object (Join-Path $OutDir '00-summary.txt')
Stop-Transcript | Out-Null
Write-Host "`nAudit complete. Results: $OutDir" -ForegroundColor Green
