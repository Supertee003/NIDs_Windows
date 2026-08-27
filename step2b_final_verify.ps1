# ============================================================
# AEGIS NIDS - STEP 2B Final Verification (false-positive safe)
# ============================================================
# This version keeps ErrorActionPreference = 'Continue' for the
# ENTIRE script, so stderr from Zig (test progress) and Python
# unittest (skipped notices) never halt the script.
#
# All pass/fail decisions are based on $LASTEXITCODE only.
# ============================================================

# IMPORTANT: keep Continue for the entire script
$ErrorActionPreference = 'Continue'

$DeployRoot = $PSScriptRoot
if (-not $DeployRoot) { $DeployRoot = (Get-Location).Path }
Write-Host "[VERIFY] AEGIS STEP 2B Final Verification"
Write-Host "[VERIFY] Deploy root: $DeployRoot"
Write-Host ""

# ============================================================
# Step 1: zig build
# ============================================================
Write-Host "[STEP 1] zig build"
& zig build 2>&1 | Out-Host
$buildExit = $LASTEXITCODE
Write-Host "[STEP 1] exit: $buildExit"
Write-Host ""

# ============================================================
# Step 2: zig build test
# ============================================================
Write-Host "[STEP 2] zig build test"
& zig build test 2>&1 | Out-Host
$testExit = $LASTEXITCODE
Write-Host "[STEP 2] exit: $testExit"
Write-Host ""

# ============================================================
# Step 3: Python wire codec self-test
# ============================================================
Write-Host "[STEP 3] python shared/wire/wire_codec.py (self-test, 8 tests)"
$WireCodecPath = Join-Path $DeployRoot "shared/wire/wire_codec.py"
if (Test-Path $WireCodecPath) {
    & python $WireCodecPath 2>&1 | Out-Host
    $pySelfExit = $LASTEXITCODE
    Write-Host "[STEP 3] exit: $pySelfExit"
} else {
    Write-Host "[STEP 3] SKIP: $WireCodecPath not found"
    $pySelfExit = -1
}
Write-Host ""

# ============================================================
# Step 4: Regenerate binary test vectors
# ============================================================
Write-Host "[STEP 4] Regenerate binary test vectors"
$GenScriptPath = Join-Path $DeployRoot "tests/contracts/generate_test_vectors.py"
if (Test-Path $GenScriptPath) {
    & python $GenScriptPath 2>&1 | Out-Host
    $genExit = $LASTEXITCODE
    Write-Host "[STEP 4] exit: $genExit"
} else {
    Write-Host "[STEP 4] SKIP: $GenScriptPath not found"
    $genExit = -1
}
Write-Host ""

# ============================================================
# Step 5: Python cross-language contract test (43 tests)
# ============================================================
Write-Host "[STEP 5] python -m unittest tests.contracts.test_wire_contract (43 tests)"
$ContractTestPath = Join-Path $DeployRoot "tests/contracts/test_wire_contract.py"
if (Test-Path $ContractTestPath) {
    # Run via the module path (tests.contracts.test_wire_contract) so
    # the binary-vector tests find their files via PROJECT_ROOT resolution.
    Push-Location $DeployRoot
    & python -m unittest tests.contracts.test_wire_contract -v 2>&1 | Out-Host
    $pyContractExit = $LASTEXITCODE
    Pop-Location
    Write-Host "[STEP 5] exit: $pyContractExit"
} else {
    Write-Host "[STEP 5] SKIP: $ContractTestPath not found"
    $pyContractExit = -1
}
Write-Host ""

# ============================================================
# Final summary
# ============================================================
Write-Host "============================================================"
Write-Host "STEP 2B FINAL VERIFICATION SUMMARY"
Write-Host "============================================================"
Write-Host "Step 1: zig build               exit = $buildExit   $(if ($buildExit -eq 0) { '[PASS]' } else { '[FAIL]' })"
Write-Host "Step 2: zig build test          exit = $testExit   $(if ($testExit -eq 0) { '[PASS]' } else { '[FAIL]' })"
Write-Host "Step 3: python wire_codec.py    exit = $pySelfExit   $(if ($pySelfExit -eq 0) { '[PASS]' } else { '[FAIL]' })"
Write-Host "Step 4: generate_test_vectors  exit = $genExit   $(if ($genExit -eq 0) { '[PASS]' } else { '[FAIL]' })"
Write-Host "Step 5: python contract test   exit = $pyContractExit   $(if ($pyContractExit -eq 0) { '[PASS]' } else { '[FAIL]' })"
Write-Host "============================================================"
Write-Host ""

$allPass = ($buildExit -eq 0) -and ($testExit -eq 0) -and ($pySelfExit -eq 0) -and ($pyContractExit -eq 0)
if ($allPass) {
    Write-Host "[FINAL] ALL CHECKS PASSED — ready to commit and push."
    Write-Host ""
    Write-Host "Suggested git commands:"
    Write-Host "  git add -A"
    Write-Host "  git commit -m `"feat: step 2b - wire header explicit encoding + cross-language refs`""
    Write-Host "  git push"
    exit 0
} else {
    Write-Host "[FINAL] AT LEAST ONE CHECK FAILED — review output above."
    exit 1
}
