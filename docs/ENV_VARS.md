# AEGIS NIDS Environment Variables (Phase 20, DOC-3)

## Core (Zig)

| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_TCP_PORT` | `12345` | TCP listener port for admin connections |
| `AEGIS_RULES_HMAC_KEY` | `AEGIS_NIDS_INTEGRITY_KEY_v1` | HMAC-SHA256 key for Rules.json tamper-evidence |

## Go Aggregator

| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_LOG_PATH` | `logs/aegis_core.ndjson` | Path to NDJSON forensic log |
| `AEGIS_API_PORT` | `9200` | REST API port |
| `AEGIS_MAX_ALERTS` | `10000` | Max unique alerts in memory |

## Python Brain

| Variable | Default | Description |
|----------|---------|-------------|
| (none currently) | — | Brain reads from hardcoded `config/Rules.json` |

## Python CLI Tools

### aegis_status.py
| Variable | Default | Description |
|----------|---------|-------------|
| (none) | — | Uses PID files + tasklist |

### aegis_metrics.py
| Variable | Default | Description |
|----------|---------|-------------|
| (none) | — | Port configurable via `--port` flag (default 9100) |

### aegis_notifier.py — Email
| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_NOTIFIER_EMAIL_HOST` | (none) | SMTP server hostname |
| `AEGIS_NOTIFIER_EMAIL_PORT` | `587` | SMTP port |
| `AEGIS_NOTIFIER_EMAIL_USER` | (none) | SMTP username |
| `AEGIS_NOTIFIER_EMAIL_PASS` | (none) | SMTP password |
| `AEGIS_NOTIFIER_EMAIL_TO` | (none) | Recipient email |

### aegis_notifier.py — Webhook
| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_NOTIFIER_WEBHOOK_URL` | (none) | Webhook URL (e.g., Slack) |
| `AEGIS_NOTIFIER_WEBHOOK_SECRET` | `""` | HMAC-SHA256 signing secret |

### aegis_notifier.py — Syslog
| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_NOTIFIER_SYSLOG_HOST` | `127.0.0.1` | Syslog server IP |
| `AEGIS_NOTIFIER_SYSLOG_PORT` | `514` | Syslog UDP port |

### aegis_api.py
| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_API_HOST` | `127.0.0.1` | Go aggregator host |
| `AEGIS_API_PORT` | `9200` | Go aggregator port |

## Port Reference

| Port | Protocol | Component | Configurable Via |
|------|----------|-----------|-------------------|
| 9999 | UDP | Python Brain | Hardcoded in `bridge_init.zig:UDP_BRAIN_PORT` |
| 12345 | TCP | Zig Core listener | `AEGIS_TCP_PORT` env var |
| 9100 | HTTP | Prometheus metrics | `aegis_metrics.py --port` |
| 9200 | HTTP | Go aggregator | `AEGIS_API_PORT` env var |
| 10001 | UDP | Dashboard UDP | Hardcoded in `udp.rs` |
