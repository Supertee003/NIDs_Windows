# AEGIS NIDS Architecture (Phase 20, DOC-1)

## Overview

AEGIS NIDS is a multi-language Network Intrusion Detection System with 8 components:

```
┌─────────────────────────────────────────────────────────────┐
│                    AEGIS NIDS Architecture                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       │
│  │ T1: Zig │  │ T2: Zig │  │ T3: Zig │  │ T4: Zig │       │
│  │ Analyze │  │ Pipe    │  │ WFP     │  │ Miniflt │       │
│  │ Engine  │  │ Sensor  │  │ Capture │  │ Reader  │       │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘       │
│       │            │            │            │             │
│       └────────────┴────────────┴────────────┘             │
│                          │                                  │
│           ┌──────────────┼──────────────┐                  │
│           ▼              ▼              ▼                   │
│  ┌─────────────┐ ┌────────────┐ ┌──────────────┐         │
│  │ C++ Bridge  │ │ Python     │ │ Go           │         │
│  │ (aegis_ipc) │ │ Brain      │ │ Aggregator   │         │
│  │ IPC + DEFCON│ │ IPS + Rules│ │ Dedup + API  │         │
│  └─────────────┘ └────────────┘ └──────────────┘         │
│                         │                                  │
│           ┌─────────────┼─────────────┐                   │
│           ▼             ▼             ▼                    │
│  ┌──────────────┐ ┌──────────┐ ┌──────────────┐          │
│  │ Rust Shield  │ │ Forensic │ │ Cython       │          │
│  │ (sec_mon)    │ │ Logger   │ │ Acceleration │          │
│  │ Tier-3 Safety│ │ NDJSON   │ │ fast_scan.pyx│          │
│  └──────────────┘ └──────────┘ └──────────────┘          │
│                                                             │
│  ┌─────────────────────────────────────────────┐           │
│  │        Python CLI Tools (scripts/)           │           │
│  │  status | alerts | rules | block | metrics   │           │
│  │  notifier | defcon | api                     │           │
│  └─────────────────────────────────────────────┘           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. Zig Core (`core/`, ~4900 lines)
- **nids_main.zig** — Entry point, 5-thread orchestration
- **nids_analyze.zig** — 3-tier threat analysis (Aho-Corasick + rules + brain)
- **nids_capture.zig** — Named pipe IPC sensor (Python → Zig)
- **windows_capture.zig** — WFP kernel traffic sensor
- **minifilter_reader.zig** — Filesystem minifilter event reader
- **pipe_monitor.zig** — Suspicious pipe name scanner
- **wfp_ioctl.zig** — WFP driver IOCTL bridge (block/unblock IPs)
- **bridge_init.zig** — C++/Rust DLL loading + UDP brain
- **forensic_log.zig** — NDJSON persistent logger with rotation
- **win32_io.zig** — Shared overlapped I/O helpers

### 2. Python Brain (`brain/windows_brain.py`)
- Receives alerts via UDP from Zig Core
- Tier-2 regex scanning
- Windows Firewall IPS (netsh advfirewall)
- Uses Cython acceleration (aegis_brain_cython)

### 3. C++ Bridge (`bridge/aegis_ipc.cpp`)
- IPC ring buffer for cross-language event passing
- DEFCON level aggregator
- IP block/unblock (B-07: implemented via netsh)

### 4. Rust Shield (`shield/`)
- Tier-3 memory safety validation
- Payload behavioral analysis

### 5. Rust Dashboard (`aegis_dashboard/`)
- egui desktop UI + axum web API
- Reads `logs/aegis_core.ndjson` (GAP-4 fix)

### 6. Cython Module (`brain/aegis_brain_cython/`)
- `fast_scan.pyx` — 6 native C functions
- Transparent Python fallback via `bridge.py`

### 7. Go Aggregator (`go/aggregator/`)
- Real-time NDJSON file watcher (fsnotify)
- Alert deduplication (SHA-256 hash)
- Session correlation (session_id)
- REST API on :9200

### 8. Python CLI Tools (`scripts/`)
- `aegis_status.py` — 5-subsystem health check
- `aegis_alerts.py` — Alert viewer + acknowledgement
- `aegis_rules.py` — Rule management + HMAC signing
- `aegis_block.py` / `aegis_unblock.py` — Manual IP block/unblock
- `aegis_metrics.py` — Prometheus /metrics endpoint (:9100)
- `aegis_notifier.py` — Email/webhook/syslog notifications
- `aegis_defcon.py` — Centralized DEFCON calculation
- `aegis_api.py` — Go aggregator REST API client

## Data Flow

1. **Traffic enters** → WFP kernel driver captures → `windows_capture.zig`
2. **Pipe input** → Python sensor → `nids_capture.zig`
3. **Analysis** → `nids_analyze.zig` (Aho-Corasick + Tier-2 + Tier-3)
4. **Alert** → `forensic_log.zig` (NDJSON) + `bridge_init.sendToBrain()` (UDP)
5. **Brain** → `windows_brain.py` receives UDP → IPS decision → log
6. **Aggregator** → Go watches NDJSON → dedup + correlation → REST API
7. **Dashboard** → reads NDJSON + queries Go API → display

## Port Allocation

| Port | Protocol | Component |
|------|----------|-----------|
| 9999 | UDP | Brain (Python) |
| 12345 | TCP | Zig Core (admin pipe listener) |
| 9100 | HTTP | Prometheus metrics |
| 9200 | HTTP | Go aggregator REST API |
| 10001 | UDP | Dashboard listener (brain forwards) |

## File Layout

```
logs/
├── aegis_core.ndjson       # Forensic log (NDJSON, rotated at 100MB)
├── aegis_core.1.ndjson     # Rotated log
├── blocked_ips.json        # Current blocked IPs
├── acknowledged_alerts.json # Alert ack state
└── payloads/               # Captured Block-event payloads
    └── <sha256-prefix>.bin
```
