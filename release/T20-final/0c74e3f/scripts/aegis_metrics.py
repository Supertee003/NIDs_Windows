#!/usr/bin/env python3
"""
aegis_metrics.py - AEGIS NIDS Prometheus Metrics Endpoint (Phase 13, UX-08)

Exposes AEGIS metrics in Prometheus text format on HTTP port 9100.
Reads from logs/aegis_core.ndjson and logs/blocked_ips.json to compute
real-time counters.

Metrics exposed:
  aegis_total_connections
  aegis_total_matches
  aegis_total_forwarded
  aegis_blocked_ips_count
  aegis_analyze_errors_total
  aegis_ruleset_version
  aegis_defcon_level
  aegis_session_count
  aegis_block_events_total
  aegis_match_events_total
  aegis_forward_events_total

Usage:
  python aegis_metrics.py                # Start HTTP server on :9100
  python aegis_metrics.py --port 9101   # Custom port
  python aegis_metrics.py --print       # Print metrics to stdout and exit
"""

import argparse
import http.server
import json
import socketserver
import sys
import time
from pathlib import Path
from collections import Counter

# ============================================================
# Configuration
# ============================================================

AEGIS_ROOT = Path(__file__).parent.parent
LOG_FILE = AEGIS_ROOT / "logs" / "aegis_core.ndjson"
BLOCKED_IPS_FILE = AEGIS_ROOT / "logs" / "blocked_ips.json"
METRICS_PORT = 9100


def read_metrics_from_logs() -> dict:
    """Parse logs/aegis_core.ndjson to compute metrics."""
    metrics = {
        "aegis_block_events_total": 0,
        "aegis_match_events_total": 0,
        "aegis_forward_events_total": 0,
        "aegis_session_count": 0,
        "aegis_analyze_errors_total": 0,
        "aegis_ruleset_version": 0,
        "aegis_last_event_ts_ms": 0,
    }

    if not LOG_FILE.exists():
        return metrics

    session_ids = set()
    ruleset_version = 0

    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue

                event_type = event.get("event", "")
                if event_type == "BLOCK":
                    metrics["aegis_block_events_total"] += 1
                elif event_type == "MATCH":
                    metrics["aegis_match_events_total"] += 1
                elif event_type == "FORWARD":
                    metrics["aegis_forward_events_total"] += 1

                sid = event.get("session_id")
                if sid:
                    session_ids.add(sid)

                rv = event.get("ruleset_version")
                if rv and rv > ruleset_version:
                    ruleset_version = rv

                ts = event.get("ts_ms", 0)
                if ts > metrics["aegis_last_event_ts_ms"]:
                    metrics["aegis_last_event_ts_ms"] = ts

        metrics["aegis_session_count"] = len(session_ids)
        metrics["aegis_ruleset_version"] = ruleset_version
    except OSError:
        pass

    return metrics


def read_blocked_ips_count() -> int:
    """Read logs/blocked_ips.json to get blocked IP count."""
    if not BLOCKED_IPS_FILE.exists():
        return 0
    try:
        data = json.loads(BLOCKED_IPS_FILE.read_text())
        return len(data) if isinstance(data, list) else 0
    except (json.JSONDecodeError, OSError):
        return 0


def generate_prometheus_metrics() -> str:
    """Generate Prometheus text format metrics."""
    m = read_metrics_from_logs()
    blocked_count = read_blocked_ips_count()

    lines = []
    # Header comments
    lines.append("# HELP aegis_block_events_total Total BLOCK events detected")
    lines.append("# TYPE aegis_block_events_total counter")
    lines.append(f"aegis_block_events_total {m['aegis_block_events_total']}")

    lines.append("")
    lines.append("# HELP aegis_match_events_total Total MATCH events detected")
    lines.append("# TYPE aegis_match_events_total counter")
    lines.append(f"aegis_match_events_total {m['aegis_match_events_total']}")

    lines.append("")
    lines.append("# HELP aegis_forward_events_total Total FORWARD events")
    lines.append("# TYPE aegis_forward_events_total counter")
    lines.append(f"aegis_forward_events_total {m['aegis_forward_events_total']}")

    lines.append("")
    lines.append("# HELP aegis_blocked_ips_count Currently blocked IPs")
    lines.append("# TYPE aegis_blocked_ips_count gauge")
    lines.append(f"aegis_blocked_ips_count {blocked_count}")

    lines.append("")
    lines.append("# HELP aegis_session_count Unique sessions observed")
    lines.append("# TYPE aegis_session_count gauge")
    lines.append(f"aegis_session_count {m['aegis_session_count']}")

    lines.append("")
    lines.append("# HELP aegis_ruleset_version Current ruleset version")
    lines.append("# TYPE aegis_ruleset_version gauge")
    lines.append(f"aegis_ruleset_version {m['aegis_ruleset_version']}")

    lines.append("")
    lines.append("# HELP aegis_last_event_timestamp_ms Timestamp of last event")
    lines.append("# TYPE aegis_last_event_timestamp_ms gauge")
    lines.append(f"aegis_last_event_timestamp_ms {m['aegis_last_event_ts_ms']}")

    lines.append("")
    lines.append("# HELP aegis_up AEGIS NIDS is running (1=up, 0=down)")
    lines.append("# TYPE aegis_up gauge")
    is_up = 1 if m['aegis_last_event_ts_ms'] > 0 else 0
    lines.append(f"aegis_up {is_up}")

    return "\n".join(lines) + "\n"


class MetricsHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for /metrics endpoint."""

    def do_GET(self):
        if self.path == "/metrics":
            metrics = generate_prometheus_metrics()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(metrics)))
            self.end_headers()
            self.wfile.write(metrics.encode("utf-8"))
        elif self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            html = b"<html><body><h1>AEGIS NIDS Metrics</h1><p><a href='/metrics'>/metrics</a></p></body></html>"
            self.wfile.write(html)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress access log


def main():
    parser = argparse.ArgumentParser(description="AEGIS NIDS Prometheus Metrics Endpoint")
    parser.add_argument("--port", type=int, default=METRICS_PORT, help="HTTP port (default: 9100)")
    parser.add_argument("--print", action="store_true", help="Print metrics and exit")
    args = parser.parse_args()

    if args.print:
        print(generate_prometheus_metrics())
        return 0

    print(f"[METRICS] Serving Prometheus metrics on http://0.0.0.0:{args.port}/metrics")

    with socketserver.TCPServer(("0.0.0.0", args.port), MetricsHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[METRICS] Shutting down...")
            httpd.shutdown()

    return 0


if __name__ == "__main__":
    sys.exit(main())
