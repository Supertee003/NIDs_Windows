[CmdletBinding()]
param(
    [string]$ExpectedLabSubnet = '192.168.126.0/24'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Get-Health {
    $raw = & python tools\aegisctl.py health --json 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($raw -join [Environment]::NewLine).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { throw 'health returned empty output' }
    try { $health = $text | ConvertFrom-Json }
    catch { throw "health returned non-JSON output: $text" }
    if ($exitCode -ne 0 -and $health.runtime_available -ne $false) {
        throw "health failed ($exitCode): $text"
    }
    return $health
}

function Test-IPv4InCidr([string]$Address, [string]$Cidr) {
    try {
        $cidrParts = $Cidr.Split('/')
        if ($cidrParts.Count -ne 2) { return $false }
        $prefix = [int]$cidrParts[1]
        if ($prefix -lt 0 -or $prefix -gt 32) { return $false }
        $addressBytes = ([System.Net.IPAddress]::Parse($Address)).GetAddressBytes()
        $networkBytes = ([System.Net.IPAddress]::Parse($cidrParts[0])).GetAddressBytes()
        if ($addressBytes.Length -ne 4 -or $networkBytes.Length -ne 4) { return $false }
        $fullBytes = [Math]::Floor($prefix / 8)
        $remainingBits = $prefix % 8
        for ($i = 0; $i -lt $fullBytes; $i++) {
            if ($addressBytes[$i] -ne $networkBytes[$i]) { return $false }
        }
        if ($remainingBits -gt 0) {
            $mask = [byte](0xFF -shl (8 - $remainingBits))
            if (($addressBytes[$fullBytes] -band $mask) -ne ($networkBytes[$fullBytes] -band $mask)) { return $false }
        }
        return $true
    } catch { return $false }
}

$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match 'VMware|VMnet' -or $_.InterfaceDescription -match 'VMware|VMnet'
} | Select-Object Name, InterfaceDescription, Status, MacAddress, ifIndex)

$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
    $_.InterfaceAlias -match 'VMware|VMnet'
} | Select-Object InterfaceAlias, IPAddress, PrefixLength, AddressState)
$labAddresses = @($addresses | Where-Object { Test-IPv4InCidr $_.IPAddress $ExpectedLabSubnet })
$natAddresses = @($addresses | Where-Object { $_.IPAddress -like '192.168.5.*' })

$health = $null
$healthError = $null
try { $health = Get-Health } catch { $healthError = $_.Exception.Message }

$runtimeAvailable = $null -ne $health -and $health.runtime_state -eq 'RUNNING'
$tier3Ready = $null -ne $health -and [bool]$health.tier3.ready
$pepReady = $null -ne $health -and [bool]$health.rust_shield.pep_ready
$hostEffect = $null -ne $health -and [bool]$health.rust_shield.host_effect_capable

$result = [ordered]@{
    proof = 'phase10_vmware_lab_preflight_read_only'
    passed = $runtimeAvailable -and $tier3Ready -and $pepReady -and -not $hostEffect -and $adapters.Count -gt 0 -and $labAddresses.Count -gt 0
    expected_lab_subnet = $ExpectedLabSubnet
    adapters = $adapters
    addresses = $addresses
    lab_addresses = $labAddresses
    adapter_found = $adapters.Count -gt 0
    lab_subnet_found = $labAddresses.Count -gt 0
    nat_addresses_detected = $natAddresses.Count -gt 0
    health_available = $null -ne $health
    health_error = $healthError
    runtime_state = if ($null -ne $health) { $health.runtime_state } else { $null }
    tier3_ready = $tier3Ready
    pep_ready = $pepReady
    provider_ready = if ($null -ne $health) { [bool]$health.rust_shield.provider_ready } else { $false }
    host_effect_capable = $hostEffect
    overall_gate = if ($null -ne $health) { [bool]$health.rust_shield.host_effect_capable -and [bool]$health.tier3.provider_ready } else { $false }
    attack_attempted = $false
    enforcement_attempted = $false
    next_step = 'Verify Kali and target VMs are attached only to the isolated VMnet, then run observe-only traffic proof. Do not run WFP block proof from this preflight.'
}

$result | ConvertTo-Json -Depth 8
if (-not $result.passed) { exit 1 }
