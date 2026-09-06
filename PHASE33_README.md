# AEGIS NIDS - Phase 33: SIEM Integration

## Overview
Forwards detection events to SIEM platforms (Splunk, Elasticsearch, syslog).
Additive module — reads from forensic ring buffer and forwards, doesn't modify detection logic.

## Risk Level: LOW
- **Additive module** — new file, doesn't touch existing code
- **Can be disabled** — set `enabled: false` in config
- **No enforcement changes** — doesn't affect BLOCK/DETECT
- **No detection changes** — doesn't modify Brain or Core

## Files Delivered

| File | Type | Purpose |
|------|------|---------|
| `siem_forwarder.zig` | Zig | Forwarder module (17 tests) |
| `siem_config.json` | JSON | Configuration template |
| `generate_siem_report.ps1` | PowerShell | Forward events from anomalous.json |
| `PHASE33_README.md` | Markdown | This documentation |

## Supported Formats

### NDJSON (default)
For Elasticsearch/Logstash:
```json
{"timestamp":1693900000,"attack_type":"SQLI","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":12345,"dst_port":80,"protocol":"TCP","severity":"Critical","policy":"BLOCK","rule_id":"R001","status":"DETECTED"}
```

### CEF (Common Event Format)
For Splunk/QRadar/ArcSight:
```
CEF:0|AEGIS|NIDS|5.0|R001|SQLI|10|src=10.0.0.1 dst=10.0.0.2 spt=12345 dpt=80 proto=TCP policy=BLOCK status=DETECTED
```

### Syslog (RFC 5424)
For rsyslog/syslog-ng:
```
<4>1 1693900000 - AEGIS NIDS - - - attack_type=SQLI src=10.0.0.1 dst=10.0.0.2 severity=Critical status=DETECTED
```

## Supported Transports

| Transport | Status | Destination Format | Use Case |
|-----------|--------|---------------------|----------|
| **file** | ✅ Implemented | `path/to/file.json` | Testing, local archival |
| **http** | ⏳ Phase 33.1 | `http://host:port/path` | Splunk HEC, Elasticsearch |
| **https** | ⏳ Phase 33.1 | `https://host:port/path` | Secure HTTP collectors |
| **tcp** | ⏳ Phase 33.1 | `host:port` | Logstash beats input |
| **udp** | ⏳ Phase 33.1 | `host:port` | Syslog collectors |

## Quick Start

### 1. Test with File Transport (default)
```powershell
# Forward all events from anomalous.json to logs/siem_forward.json
powershell -ExecutionPolicy Bypass -File .\generate_siem_report.ps1

# View forwarded events
type logs\siem_forward.json | Select-Object -First 5
```

### 2. Forward as CEF format
```powershell
powershell -ExecutionPolicy Bypass -File .\generate_siem_report.ps1 -Format cef -Output logs/siem_cef.txt
```

### 3. Forward as Syslog format
```powershell
powershell -ExecutionPolicy Bypass -File .\generate_siem_report.ps1 -Format syslog -Output logs/siem_syslog.txt
```

## Configuration

Edit `siem_config.json`:
```json
{
  "siem_forwarder": {
    "enabled": true,
    "format": "ndjson",
    "transport": "file",
    "destination": "logs/siem_forward.json",
    "batch_size": 100,
    "flush_interval_ms": 5000
  }
}
```

## Integration Examples

### Splunk (HTTP Event Collector)
```json
{
  "siem_forwarder": {
    "enabled": true,
    "format": "cef",
    "transport": "http",
    "destination": "http://splunk-hec:8088/services/collector",
    "batch_size": 100
  }
}
```

### Elasticsearch (Bulk API)
```json
{
  "siem_forwarder": {
    "enabled": true,
    "format": "ndjson",
    "transport": "http",
    "destination": "http://elastic:9200/aegis-events/_bulk",
    "batch_size": 100
  }
}
```

### Logstash (TCP beats input)
```json
{
  "siem_forwarder": {
    "enabled": true,
    "format": "ndjson",
    "transport": "tcp",
    "destination": "logstash-host:5044",
    "batch_size": 50
  }
}
```

### rsyslog (UDP syslog)
```json
{
  "siem_forwarder": {
    "enabled": true,
    "format": "syslog",
    "transport": "udp",
    "destination": "syslog-host:514"
  }
}
```

## Statistics

The forwarder tracks:
- `total_events_read` — events read from forensic log
- `total_events_forwarded` — successfully forwarded
- `total_events_failed` — failed after retries
- `total_batches_sent` — number of batches sent
- `total_retries` — retry attempts
- `last_forward_ms` — last batch send duration

Success rate = forwarded / (forwarded + failed) × 100

## Verification

```powershell
# Test Zig module compiles
zig test core\siem_forwarder.zig -lc
# Expected: All 17 tests passed

# Run forwarder
powershell -ExecutionPolicy Bypass -File .\generate_siem_report.ps1

# Check output
type logs\siem_forward.json | Measure-Object
```

## Next Phase

After Phase 33 is verified:
- **Phase 34**: Config Hot-Reload (MEDIUM risk)
- Phase 33.1: HTTP/TCP/UDP transport implementation (future)
