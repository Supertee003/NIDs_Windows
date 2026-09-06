# AEGIS NIDS - Phase 40: Compliance Reporting

## Overview
Generates compliance reports from forensic logs for audit purposes.
Read-only operation — never modifies the running system.

## Risk Level: LOW
- **Read-only**: Reads logs/anomalous.json only, no writes to system
- **No enforcement changes**: Doesn't touch detection/blocking logic
- **No detection changes**: Doesn't modify Brain or Core
- **Output isolated**: Reports go to reports/ directory

## Files Delivered

| File | Type | Purpose |
|------|------|---------|
| `compliance_reporter.zig` | Zig | Programmatic API (24 tests) |
| `generate_compliance_report.ps1` | PowerShell | CLI generator |
| `PHASE40_README.md` | Markdown | This documentation |

## Supported Frameworks

### PCI-DSS (10 controls)
| ID | Name | Check |
|----|------|-------|
| PCI-10.1 | Audit Logging Enabled | total_detected > 0 |
| PCI-10.2 | Security Event Logging | total_detected > 0 |
| PCI-10.3 | Event Detail Capture | total_detected > 0 |
| PCI-10.4 | Time Synchronization | always_true |
| PCI-10.5 | Audit Log Protection | always_true |
| PCI-10.6 | Log Review | total_detected > 0 |
| PCI-10.7 | Log Retention | always_true |
| PCI-11.4 | Vulnerability Scanning | total_detected > 0 |
| PCI-11.5 | Intrusion Detection | total_detected > 0 |
| PCI-12.10 | Incident Response | total_blocked > 0 |

### HIPAA (10 controls)
| ID | Name | Check |
|----|------|-------|
| HIPAA-164.312(b) | Audit Controls | total_detected > 0 |
| HIPAA-164.312(c)(1) | Integrity Controls | total_detected > 0 |
| HIPAA-164.312(d) | Person Authentication | always_true |
| HIPAA-164.312(e)(1) | Transmission Security | total_blocked > 0 |
| HIPAA-164.312(e)(2)(ii) | Encryption | always_true |
| HIPAA-164.308(a)(1)(ii)(C) | Sanction Policy | always_true |
| HIPAA-164.308(a)(3) | Workforce Security | always_true |
| HIPAA-164.308(a)(5) | Security Awareness | always_true |
| HIPAA-164.308(a)(6) | Security Incident | total_blocked > 0 |
| HIPAA-164.312(a)(1) | Access Control | total_blocked > 0 |

### ISO 27001 (12 controls)
| ID | Name | Check |
|----|------|-------|
| ISO-A.8.1.1 | Asset Inventory | always_true |
| ISO-A.8.2.1 | Classification | always_true |
| ISO-A.9.1.1 | Access Control Policy | always_true |
| ISO-A.10.1.1 | Network Controls | total_detected > 0 |
| ISO-A.12.1.1 | Operational Procedures | always_true |
| ISO-A.12.2.1 | Malware Detection | total_detected > 0 |
| ISO-A.12.4.1 | Event Logging | total_detected > 0 |
| ISO-A.12.4.3 | Administrator Logs | total_detected > 0 |
| ISO-A.13.1.1 | Network Security Controls | total_blocked > 0 |
| ISO-A.13.2.1 | Information Transfer Policies | always_true |
| ISO-A.16.1.1 | Incident Management | total_blocked > 0 |
| ISO-A.16.1.2 | Incident Reporting | total_detected > 0 |

## Quick Start

### 1. List Available Frameworks
```powershell
powershell -ExecutionPolicy Bypass -File .\generate_compliance_report.ps1 -ListFrameworks
```

### 2. Generate Report for Specific Framework
```powershell
powershell -ExecutionPolicy Bypass -File .\generate_compliance_report.ps1 -Framework PCI-DSS
```

### 3. Generate Reports for ALL Frameworks
```powershell
powershell -ExecutionPolicy Bypass -File .\generate_compliance_report.ps1
```

### 4. View Generated Reports
```powershell
# List all reports
Get-ChildItem reports\

# View specific report
type reports\PCI-DSS_20260905_103000.json
```

## Report Output Format

Each report is saved as JSON to `reports/<framework>_<timestamp>.json`:

```json
{
  "framework": "PCI-DSS",
  "name": "PCI-DSS (Payment Card Industry Data Security Standard)",
  "generated_at": "2026-09-05T10:30:00.000Z",
  "compliance_score": 90.0,
  "is_compliant": true,
  "controls_checked": 10,
  "controls_passed": 9,
  "controls_failed": 1,
  "statistics": {
    "total_events": 90,
    "total_detected": 90,
    "total_blocked": 5,
    "total_block_failed": 0,
    "detection_rate_pct": 100.0,
    "block_success_rate_pct": 100.0,
    "unique_src_ips": 12,
    "attack_breakdown": {
      "sqli": 5, "xss": 10, "path_traversal": 5, "log4j": 5,
      "rfi": 5, "port_scan": 5, "brute_force": 5, "dns_exfil": 5, "syn_flood": 5
    },
    "severity_breakdown": {
      "critical": 20, "high": 30, "medium": 25, "low": 15
    }
  },
  "control_results": [
    { "id": "PCI-10.1", "name": "Audit Logging Enabled", "check": "total_detected > 0", "passed": true },
    ...
  ]
}
```

## Compliance Score Calculation

- **Score**: (controls_passed / controls_checked) × 100
- **Compliant threshold**: ≥ 80%
- **Non-compliant**: < 80%

## Statistics Computed

### Event Statistics
- Total events
- Total detected (DETECTED + BLOCKED + ALERT + BLOCK_FAILED)
- Total blocked successfully (BLOCK_OK / BLOCKED)
- Total block failures (BLOCK_FAILED)
- Total alerts (ALERT)
- Detection rate (%)
- Block success rate (%)

### Attack Breakdown (9 types)
- SQLi, XSS, Path Traversal, Log4j, RFI
- Port Scan, Brute Force, DNS Exfil, SYN Flood

### Severity Breakdown
- Critical, High, Medium, Low

### Network Statistics
- Unique source IPs observed

## Verification Checklist

- [ ] `compliance_reporter.zig` compiles (`zig test compliance_reporter.zig -lc`)
- [ ] All 24 unit tests pass
- [ ] `generate_compliance_report.ps1` runs without errors
- [ ] Reports generated in `reports/` directory
- [ ] JSON format is valid (parseable by `ConvertFrom-Json`)
- [ ] Compliance scores computed correctly
- [ ] Control checks evaluate correctly

## Zig Integration (Optional)

The `compliance_reporter.zig` module provides a programmatic API:

```zig
const compliance = @import("compliance_reporter.zig");

// Initialize
compliance.init(allocator);
defer compliance.shutdown();

// Generate PCI-DSS report
const report = try compliance.generateReport(.pci_dss);

// Check compliance
if (report.isCompliant()) {
    std.log.info("PCI-DSS: COMPLIANT ({d:.2}%)", .{report.compliance_score});
} else {
    std.log.warn("PCI-DSS: NON-COMPLIANT ({d:.2}%)", .{report.compliance_score});
}

// Save as JSON
var reporter = compliance.ComplianceReporter.init(allocator);
defer reporter.deinit();
const path = try reporter.saveReportJson(report);
std.log.info("Report saved: {s}", .{path});
```

## Troubleshooting

### "No forensic log found"
- Run AEGIS first to generate events: `.\scripts\run_aegis.bat`
- Generate test events: `python phase29_attack_generator.py --attack all --count 10`

### "Compliance score is 0%"
- No events in log → most controls fail (need `total_detected > 0`)
- Generate traffic first, then re-run report

### "All controls pass with score 100%"
- This is expected when log has events AND blocking works
- Verify by checking `controls_passed` matches expected count

### "JSON output is empty"
- Check if `logs/anomalous.json` exists
- Verify log file has valid NDJSON format

## Next Phase

After Phase 40 is verified:
- **Phase 33**: SIEM Integration (LOW risk, additive)
- **Phase 34**: Config Hot-Reload (MEDIUM risk)
