# RB-010: Telemetry Export Setup

## Objective
Set up telemetry export from AEGIS NIDS to external monitoring systems. This runbook covers configuring OpenTelemetry, Prometheus, and SIEM CEF exports.

## Prerequisites
- AEGIS NIDS running with telemetry export enabled
- External monitoring system endpoint (OTLP collector, Prometheus scraper, SIEM)
- Operator access to configuration

## Steps

1. **Configure OpenTelemetry export**
   - Set OTLP collector endpoint in config:
     ```ini
     [telemetry]
     otlp_endpoint = http://otlp-collector:4317
     ```
   - Each pipeline stage produces a span with:
     - trace_id (16 bytes, hex-encoded)
     - span_id (8 bytes, hex-encoded)
     - attributes (event_id, rule_id, action, verdict, severity, confidence, latency)
     - duration (end_ms - start_ms = latency in ms)
     - status (OK=1)

2. **Configure Prometheus export**
   - Set Prometheus scrape endpoint:
     ```ini
     [telemetry]
     prometheus_endpoint = :9100
     prometheus_path = /metrics
     ```
   - Metrics exposed (text exposition format):
     ```
     # HELP aegis_events_total Total events processed by action
     # TYPE aegis_events_total counter
     aegis_events_total{action="block"} 10
     aegis_events_total{action="alert"} 20

     # HELP aegis_event_latency_us Event processing latency in microseconds
     # TYPE aegis_event_latency_us gauge
     aegis_event_latency_us{verdict="malicious"} 5000

     # HELP aegis_event_confidence Event confidence score (0-100)
     # TYPE aegis_event_confidence gauge
     aegis_event_confidence{severity="critical"} 85
     ```

3. **Configure SIEM CEF export**
   - Set SIEM endpoint:
     ```ini
     [telemetry]
     siem_endpoint = syslog://siem-collector:514
     siem_format = cef
     ```
   - CEF format: `CEF:0|AEGIS|NIDS|1.0|<rule_id>|<name>|<severity>|<extensions>`
   - Severity mapping: critical=9, high=7, medium=5, low=3
   - Extensions: src=<ip>, act=<action>, event_id=<id>, verdict=<v>, cnf=<confidence>

4. **Verify single source of truth**
   - All 3 formats derive from the SAME TelemetryEvent
   - Verify same event_id across formats:
     ```
     otel.attr_event_id == cef.ext_event_id
     ```
   - Verify same action across formats:
     ```
     otel.attr_action == prom[0].labels[0].value == cef.ext_action
     ```
   - No data drift between formats

5. **Test the export**
   - Generate a test event:
     ```
     event = TelemetryEvent{
         .event_type = .event_blocked,
         .event_id = 42,
         .action = "block",
         .verdict = "malicious",
         .severity = "critical",
         .confidence = 85,
         .latency_us = 5000,
     }
     ```
   - Verify OTLP span generated (trace_id 16 bytes, span_id 8 bytes)
   - Verify Prometheus metrics (3 metrics: counter, 2 gauges)
   - Verify CEF event (severity=9, sig_id from rule_id)

6. **Monitor export health**
   - Check export queue depth (should be low)
   - Check export error rate (should be 0)
   - Verify all 3 sinks are receiving data

7. **Record setup in audit trail**
   - Audit trail records: action=config_reload, detail="telemetry export setup"
   - Include the configured endpoints in the detail field

## Verification
- OpenTelemetry: spans have 16-byte trace_id, 8-byte span_id, 7 attributes, OK status
- Prometheus: 3 metrics per event (counter + 2 gauges), labels match action/verdict/severity
- SIEM CEF: version=0, vendor="AEGIS", product="NIDS", severity mapped correctly
- Single source: same event_id, action, verdict, severity across all 3 formats
- No data drift between formats

## Rollback
To disable telemetry export:
1. Comment out the telemetry section in config:
   ```ini
   [telemetry]
   # otlp_endpoint = ...
   # prometheus_endpoint = ...
   # siem_endpoint = ...
   ```
2. Hot reload config (see RB-009)
3. Verify exports stop
4. External systems will show no new data

## Notes
- Single source of truth: one TelemetryEvent -> 3 export formats
- OpenTelemetry: OTLP-style spans (trace_id 16B, span_id 8B)
- Prometheus: text exposition format (# HELP, # TYPE, metric_name{labels} value)
- SIEM CEF: `CEF:0|AEGIS|NIDS|1.0|sig_id|name|severity|extension`
- Severity mapping: critical=9, high=7, medium=5, low=3 (CEF scale 0-9)
- Latency: span duration = latency_us / 1000 (ms)

## References
- G15: `core/telemetry_export_proof.zig` - Telemetry export proof
- G16: `core/siem_integration_proof.zig` - SIEM integration (ingestion direction)
- G14: `core/audit_trail_proof.zig` - Audit trail (records config changes)
