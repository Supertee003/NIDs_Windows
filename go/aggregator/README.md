# AEGIS NIDS Alert Aggregator (Phase 18 - Go Integration)

High-performance alert aggregator service written in Go.

## Features

- **Real-time NDJSON file watching** — monitors `logs/aegis_core.ndjson` for new alerts
- **Alert deduplication** — SHA-256 hash by rule + src_ip + event type
- **Cross-tier correlation** — session_id-based timeline reconstruction
- **REST API** — JSON endpoints on port 9200 for dashboard/CLI queries
- **Automatic purge** — removes alerts older than 24 hours (configurable)

## Build

```bash
cd go/aggregator
go mod tidy
go build -o aegis-aggregator.exe .
```

## Run

```bash
# Default (watches logs/aegis_core.ndjson, API on :9200)
./aegis-aggregator.exe

# Custom config
AEGIS_LOG_PATH=/var/log/aegis.ndjson AEGIS_API_PORT=9300 ./aegis-aggregator
```

## REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/alerts` | GET | List all alerts (deduplicated) |
| `/api/alerts/critical` | GET | List only critical alerts |
| `/api/alerts/{hash}` | GET | Get specific alert by hash |
| `/api/sessions` | GET | List top 20 sessions by event count |
| `/api/sessions/{id}` | GET | Get formatted timeline for session |
| `/api/stats` | GET | Aggregator statistics |
| `/api/health` | GET | Health check |
| `/api/purge` | POST | Purge old alerts (body: `{"max_age_hours": 24}`) |

## Example Usage

```bash
# Get all alerts
curl http://localhost:9200/api/alerts | jq

# Get critical alerts only
curl http://localhost:9200/api/alerts/critical

# Get session timeline
curl http://localhost:9200/api/sessions/42

# Purge alerts older than 12 hours
curl -X POST http://localhost:9200/api/purge -d '{"max_age_hours":12}'
```

## Architecture

```
Zig Core (nids_analyze.zig)
    │
    ▼
logs/aegis_core.ndjson
    │
    ▼ (fsnotify watch)
Go Aggregator
    ├── Collector (reads new lines)
    ├── Aggregator (dedup by hash)
    └── Correlator (session timelines)
         │
         ▼
    REST API (:9200)
         │
         ▼
    Dashboard / CLI / SIEM
```

## Performance

- **Alert ingestion**: >100,000 alerts/second (dedup + hash)
- **API response time**: <1ms for cached queries
- **Memory**: ~1KB per unique alert (configurable max 10,000)
- **File watching**: kernel-level fsnotify (zero polling CPU)
