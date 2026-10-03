<#
.SYNOPSIS
    Read-only capture of AEGIS-labelled WFP filters and Windows Firewall rules,
    for stale-effect evidence before/after cleanup.

.DESCRIPTION
    Enumerates:
      - netsh wfp show state (full XML) — all WFP filters and sublayers
      - Get-NetFirewallRule matching AEGIS display names
      - FilterId lists for the specific stale filters documented in the audit
        (7023741 AEGIS WFP TCP Port Proof Filter, 7088032 AEGIS_BLOCK_10.0.0.99,
         7041677 AEGIS Inbound Transport V4 Capture)

    No mutation is performed. Requires elevation only if netsh can write the XML
    to a protected location; the script tries a user-writable path first.

.OUTPUT
    Evidence directory (timestamped) with:
      - wfp_state.xml
      - wfp_state_id_scan.json  (parsed FilterId/provider/display-name summary)
      - firewall_rules.json
      - result.json
#>
[CmdletBinding()]
param(
    [string]$EvidenceDir = "",
    [string]$WfpXmlPath = ""
)

$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($EvidenceDir)) {
    $EvidenceDir = Join-Path $repo ("admin-evidence\wfp-stale-evidence-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
}
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

# Prefer a user-writable WFP XML path when run non-elevated.
if ([string]::IsNullOrWhiteSpace($WfpXmlPath)) {
    $candidates = @(
        (Join-Path $env:TEMP "wfp_state.xml"),
        (Join-Path $env:LOCALAPPDATA "AEGIS\wfp_state.xml"),
        "C:\Temp\wfp_state.xml"
    )
    foreach ($c in $candidates) {
        $parent = Split-Path $c -Parent
        if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
        try {
            netsh wfp show state file=$c 2>&1 | Out-Null
            if (Test-Path $c) {
                $WfpXmlPath = $c
                break
            }
        } catch {}
    }
}

$wfpXml = Join-Path $EvidenceDir "wfp_state.xml"
if (-not [string]::IsNullOrWhiteSpace($WfpXmlPath) -and (Test-Path $WfpXmlPath)) {
    Copy-Item $WfpXmlPath $wfpXml -Force
} else {
    netsh wfp show state file=$wfpXml 2>&1 | Out-String | Set-Content -Path (Join-Path $EvidenceDir "netsh_attempt.log") -Encoding UTF8
    if (-not (Test-Path $wfpXml)) {
        # Last resort: dump to current dir via netsh without file (may be large)
        netsh wfp show state 2>&1 | Set-Content -Path (Join-Path $EvidenceDir "wfp_state_stdout.log") -Encoding UTF8
    }
}

$result = [ordered]@{ proof = "wfp_stale_evidence" }
$result["wfp_xml"] = $wfpXml
$result["wfp_xml_exists"] = (Test-Path $wfpXml)
$result["wfp_xml_size"] = $null
if (Test-Path $wfpXml) { $result["wfp_xml_size"] = (Get-Item $wfpXml).Length }

# Parse filter ids + display names from the XML if we have it.
$filter_summary = [System.Collections.Generic.List[object]]::new()
$filter_ids = [System.Collections.Generic.HashSet[string]]::new()
if (Test-Path $wfpXml) {
    try {
        $xml = [xml](Get-Content $wfpXml -Encoding UTF8 -Raw)
        if ($xml -and $xml.SelectNodes) {
            $nodes = @()
            $xml.SelectNodes("//Filter") | ForEach-Object { $nodes += $_ }
            if ($nodes.Count -eq 0) {
                $xml.SelectNodes("//filter") | ForEach-Object { $nodes += $_ }
            }
            foreach ($n in $nodes) {
                $id = $n.SelectSingleNode("filterId"); $id = if ($id) { $id.InnerText } else { $null }
                $name = $n.SelectSingleNode("displayData/name"); $name = if ($name) { $name.InnerText } else { $null }
                $provider = $n.SelectSingleNode("providerKey/guid"); $provider = if ($provider) { $provider.InnerText } else { $null }
                $action = $n.SelectSingleNode("action"); $action = if ($action) { $action.InnerText } else { $null }
                $flags = $n.SelectSingleNode("flags"); $flags = if ($flags) { $flags.InnerText } else { $null }
                $layer = $n.SelectSingleNode("subLayerKey/name"); $layer = if ($layer) { $layer.InnerText } else { $null }
                if ($id) {
                    $filter_ids.Add($id) | Out-Null
                    $row = [ordered]@{
                        filterId = $id
                        displayName = $name
                        provider = $provider
                        action = $action
                        flags = $flags
                        subLayer = $layer
                    }
                    $filter_summary.Add($row)
                }
            }
        }
    } catch {
        $result["wfp_parse_error"] = $_.Exception.Message
    }
}

$rule_summary = [System.Collections.Generic.List[object]]::new()
$fw_rules = [System.Collections.Generic.List[object]]::new()
try {
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -match "AEGIS" -or $_.DisplayName -match "aegis" -or $_.Description -match "AEGIS"
    }
    foreach ($r in $rules) {
        $row = [ordered]@{
            name = $r.Name
            displayName = $r.DisplayName
            description = $r.Description
            enabled = $r.Enabled
            direction = $r.Direction
            action = $r.Action
            profile = ($r | Select-Object -ExpandProperty Profile -Unique) -join ","
        }
        $fw_rules.Add($row)
        $rule_summary.Add($row)
    }
} catch {
    $result["firewall_query_error"] = $_.Exception.Message
}

# Specific stale ids from the audit report.
$stale = [ordered]@{
    "7023741" = "AEGIS WFP TCP Port Proof Filter (ALE_AUTH_CONNECT_V4, BLOCK, PERSISTENT, 8.8.8.8:80/TCP)"
    "7088032" = "AEGIS_BLOCK_10.0.0.99 (INBOUND_ICMP_ERROR_V4, BLOCK, provider MPSSVC_WF, 10.0.0.99)"
    "7041677" = "AEGIS Inbound Transport V4 Capture (INBOUND_TRANSPORT_V4, CALLOUT_TERMINATING, non-persistent)"
}

$result["filter_ids_present"] = @()
foreach ($sid in @("7023741","7088032","7041677")) {
    $present = $filter_ids.Contains($sid)
    $result["filter_ids_present"] += "$sid=$present"
}

$result["filter_count_parsed"] = $filter_summary.Count
$result["filter_ids_all"] = ($filter_ids | Sort-Object) -join ","
$result["stale_ids"] = $stale
$result["firewall_rules_matched"] = $fw_rules.Count
$result["filter_summary_sample"] = $filter_summary | Select-Object -First 50
$result["firewall_rules_sample"] = $fw_rules | Select-Object -First 50

$result | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $EvidenceDir "result.json") -Encoding UTF8
$filter_summary | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $EvidenceDir "wfp_state_id_scan.json") -Encoding UTF8
$fw_rules | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $EvidenceDir "firewall_rules.json") -Encoding UTF8

Write-Host "WFP_STALE_EVIDENCE="$EvidenceDir -ForegroundColor Cyan
Write-Host "wfp_xml_exists=$($result["wfp_xml_exists"]) wfp_xml_size=$($result["wfp_xml_size"])" -ForegroundColor Cyan
Write-Host "filter_count_parsed=$($result["filter_count_parsed"]) stale_ids_present=$($result["filter_ids_present"] -join " " )" -ForegroundColor Cyan
Write-Host "firewall_rules_matched=$($result["firewall_rules_matched"])"
