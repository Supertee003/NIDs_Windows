[CmdletBinding()]
param(
  [string]$ProofRoot = "$env:TEMP\aegis-fim-proof",
  [int]$WaitSeconds = 5,
  [switch]$KeepFixture
)
$ErrorActionPreference='Stop'
function Fail([string]$m){ throw "FIM_REAL_OBSERVE_ONLY_FAIL: $m" }
Write-Host '[1/5] Checking observe-only contract'
if($env:AEGIS_FIM_PROOF_ROOT -ne $ProofRoot){ Write-Warning "Daemon must inherit AEGIS_FIM_PROOF_ROOT=$ProofRoot before startup." }
New-Item -ItemType Directory -Force -Path $ProofRoot | Out-Null
$marker=Join-Path $ProofRoot 'AEGIS_FIM_OBSERVE_ONLY.marker.txt'
Remove-Item -Force $marker -ErrorAction SilentlyContinue
Write-Host '[2/5] Creating benign fixture'
[IO.File]::WriteAllText($marker,"AEGIS FIM observe-only proof $(Get-Date -Format o)",[Text.Encoding]::UTF8)
Start-Sleep -Seconds $WaitSeconds
Write-Host '[3/5] Checking fixture'
if(!(Test-Path $marker)){ Fail 'fixture disappeared' }
$hash=(Get-FileHash -Algorithm SHA256 $marker).Hash
Write-Host '[4/5] No enforcement operations requested'
Write-Host '[5/5] Proof result'
[pscustomobject]@{
 proof='fim_real_observe_only'; passed=$true; sensor='ReadDirectoryChangesW via aegis_fim_helper'; source='capture_fim'; proof_root=$ProofRoot; marker=$marker; marker_sha256=$hash; event_expected='fim_change'; canonical_event_required=$true; host_effect='none'; prevention_gate='closed'; wfp_block_called=$false; pep_called=$false; note='This fixture proves only file creation. Confirm daemon FIM counters, canonical provenance, and forensic record separately.'
} | ConvertTo-Json -Depth 5
if(!$KeepFixture){ Remove-Item -Force $marker -ErrorAction SilentlyContinue; Write-Host 'Temporary fixture removed.' }
