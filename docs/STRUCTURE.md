# AEGIS NIDS — Project Structure

## Overview

```
NIDs_Windows/
├── CMakeLists.txt           # C++ Bridge build (cmake)
├── build.zig                # Zig Core build (zig build)
├── Cargo.toml               # Rust Tier-3 Shield build (cargo)
├── Cargo.lock
├── go.mod                   # Go Nose module
├── .gitignore
│
├── bridge/                  # 🌉 C++ Bridge — IPC Hub
│   ├── aegis_bridge_main.cpp    # Bridge standalone executable
│   ├── aegis_ipc.cpp            # IPC shared library implementation
│   ├── aegis_ipc.hpp            # IPC header (6 C-ABI exports)
│   ├── aegis_packet_parser.cpp  # Packet parsing engine
│   ├── aegis_packet_parser.hpp  # Packet parser header
│   ├── aegis_bridge_test.cpp    # Bridge unit test
│   ├── aegis_bindings.zig       # Zig FFI bindings for Bridge
│   ├── aegis_bridge_ffi.rs      # Rust FFI bindings for Bridge
│   └── aegis_bridge_ctypes.py   # Python ctypes bindings for Bridge
│
├── core/                    # ⚙️ Zig Core — Packet Engine
│   ├── nids_main.zig            # Main entry point (5 threads)
│   ├── nids_capture.zig         # Npcap packet capture
│   ├── nids_analyze.zig         # Pattern matching engine
│   ├── windows_capture.zig      # Windows-specific capture
│   ├── pipe_monitor.zig         # Named pipe IPC monitor
│   └── minifilter_reader.zig    # Minifilter event reader
│
├── nose/                    # 👃 Go Nose — Headless Performance Collector
│   └── windows_perf.go          # 3 goroutines: Resource + Traffic + ThreatMap
│                                  # Output: JSON to stdout (no TUI, no DEFCON)
│
├── mouth/                   # 🛡️ Rust Mouth — Sole DEFCON Owner + Security
│   ├── windows_sec_monitor.rs   # Sole DEFCON TUI binary (single window)
│   └── aegis_mouth_tui.rs       # Enhanced TUI with ETW/Process monitor stubs
│
├── src/                     # 📦 Tier-3 FFI Library (Cargo expects this)
│   └── lib.rs                   # sec_monitor.dll: validate_payload_safety (4 checks)
│
├── brain/                   # 🧠 Python Brain — Detection Engine
│   ├── windows_brain.py         # Brain process (regex + IPS + Bridge IPC)
│   └── cython/                  # Cython hot-spot optimization
│       ├── aegis_hotspot.pyx
│       ├── aegis_hotspot.pxd
│       └── setup.py
│
├── scripts/                 # 🚀 Launcher & Management
│   ├── run_aegis.bat            # Full system launcher (5 phases)
│   ├── stop_aegis.bat           # Graceful shutdown (Brain→Nose→Mouth→Core→Bridge)
│   ├── aegis_status.bat         # Quick status (--watch, --json)
│   ├── build_all.bat            # Build all components
│   ├── build_drivers.bat        # Build kernel drivers
│   ├── install_drivers.bat      # Install kernel drivers
│   ├── aegis_console.py         # Command Control Center v7.0 (10 menus)
│   ├── aegis_daemon.py          # Background daemon
│   ├── aegis_graph.py           # Threat graph visualization
│   ├── Dashboard.py             # Web dashboard
│   └── tests/                   # Test Suites
│       ├── aegis_nose_test.py       # Nose-only tests (headless, no DEFCON)
│       ├── aegis_mouth_test.py      # Mouth-only tests (sole DEFCON owner)
│       └── test_e2e.py              # End-to-end integration test
│
├── config/                  # ⚙️ Configuration
│   ├── Rules.json               # Detection rules
│   ├── Back_Rules.json          # Backup rules
│   └── threat_graph.html        # Threat map visualization
│
├── drivers/                 # 🔧 Windows Kernel Drivers
│   ├── minifilter/              # Minifilter (C) — file system monitoring
│   │   ├── aegis_minifilter.c
│   │   ├── aegis_minifilter.h
│   │   ├── aegis_minifilter_comm.c
│   │   ├── aegis_minifilter_file.c
│   │   ├── aegis_minifilter_proc.c
│   │   └── aegis_minifilter.inf
│   ├── minifilter_cpp/          # Minifilter (C++) — C++ wrapper
│   ├── wfp_callout/             # WFP Callout (C) — network filtering
│   └── wfp_callout_cpp/         # WFP Callout (C++) — C++ wrapper
│
├── lib/                     # 📚 Third-Party UI Libraries
│   ├── vis-9.1.2/               # Vis.js network graph
│   ├── bootstrap-5.0.0-beta3/  # Bootstrap CSS/JS
│   ├── tom-select/              # Tom Select dropdown
│   └── bindings/                # JS bindings
│
├── ui-vaadin/               # 🖥️ Vaadin Web Dashboard (Java)
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/aegis/nids/  # Java dashboard views
│       └── rust/                  # Rust WASM module
│
├── build/                   # 🔨 C++ Build Output (gitignored)
├── zig-out/                 # 🔨 Zig Build Output (gitignored)
│   └── bin/
│       ├── aegis-nids.exe
│       ├── sec_monitor.dll
│       └── aegis_ipc.dll
├── target/                  # 🔨 Cargo Build Output (gitignored)
│   └── release/
│       └── sec_monitor.dll
├── logs/                    # 📋 Runtime Logs (gitignored)
│   ├── anomalous.json           # Detected anomalies
│   └── pids/                    # PID files
│       ├── bridge.pid
│       ├── core.pid
│       ├── brain.pid
│       ├── nose.pid
│       ├── mouth.pid
│       └── dashboard.pid
│
└── docs/                    # 📖 Documentation
    └── STRUCTURE.md             # This file
```

## Subsystem Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     AEGIS NIDS v2.0                              │
│                                                                  │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐                    │
│  │  BRIDGE  │   │   CORE   │   │  BRAIN   │                    │
│  │  (C++)   │   │  (Zig)   │   │ (Python) │                    │
│  │ IPC Hub  │   │ Engine   │   │ Detection│                    │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘                    │
│       │              │              │                            │
│       └──────┬───────┴──────┬───────┘                            │
│              │              │                                    │
│  ┌───────────┴──────┐  ┌───┴──────────────┐                   │
│  │      NOSE        │  │      MOUTH        │                   │
│  │      (Go)        │  │     (Rust)        │                   │
│  │  Headless        │  │  Sole DEFCON      │                   │
│  │  Collector       │  │  Owner + TUI      │                   │
│  │  ┌────────────┐ │  │  ┌──────────────┐ │                   │
│  │  │ Resource   │ │  │  │ DEFCON Calc  │ │                   │
│  │  │ Traffic    │ │  │  │ TUI Display  │ │                   │
│  │  │ ThreatMap  │ │  │  │ Tier-3 Shield│ │                   │
│  │  └────────────┘ │  │  │ ETW (stub)   │ │                   │
│  │  JSON → stdout  │  │  │ Proc (stub)  │ │                   │
│  │  (no window)    │  │  └──────────────┘ │                   │
│  └─────────────────┘  │  (single window)  │                   │
│                        └────────────────────┘                   │
└──────────────────────────────────────────────────────────────────┘
```

## Startup Order
1. Bridge (C++) — IPC hub, 3s wait
2. Core (Zig) — NIDS engine, 3s wait
3. Brain (Python) — Detection rules, 2s wait
4. Nose (Go) — Headless collector (no window)
5. Mouth (Rust) — Sole DEFCON TUI (single window)
6. Stabilize — 3s wait

## Shutdown Order
1. Brain → 2. Nose → 3. Mouth → 4. Core → 5. Bridge (Bridge last as IPC hub)

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Nose is headless | No TUI, no popup window. Outputs JSON to stdout for Bridge/Brain |
| Mouth is sole DEFCON owner | Only Mouth calculates and displays DEFCON. No overlap with Nose |
| Nose reads only attack_type | Nose builds ThreatMap only. Does NOT parse severity/policy/tier |
| Mouth parses all fields | Mouth reads severity/policy/tier for DEFCON calculation |
| Nose uses `start /B` | Background mode — no console window popup |
| Mouth uses `start` | Foreground — single TUI console window |
| kernel >= 3 for DEFCON 1 | Consistent across all Rust files (was inconsistent: mouth_tui had >= 1) |

## Build Commands

| Component | Build Command | Output |
|-----------|--------------|--------|
| Bridge (C++) | `cmake -B build && cmake --build build --config Release` | `build/Release/aegis_ipc.dll`, `aegis_bridge.exe` |
| Core (Zig) | `zig build` | `zig-out/bin/aegis-nids.exe` |
| Shield (Rust) | `cargo build --release` | `target/release/sec_monitor.dll` |
| Mouth (Rust) | `rustc -O mouth/windows_sec_monitor.rs -o windows_sec_monitor.exe` | `windows_sec_monitor.exe` |
| Nose (Go) | `go build -o aegis-nose.exe nose/main.go + model.go + collectors.go + styles.go` | `aegis-nose.exe` |

## Test Commands

| Test | Command | Tests |
|------|---------|-------|
| Nose | `python scripts/tests/aegis_nose_test.py` | Resource, Traffic, ThreatMap, No overlap |
| Mouth | `python scripts/tests/aegis_mouth_test.py` | DEFCON, Tier-3 FFI, No overlap |
| E2E | `python scripts/tests/test_e2e.py` | Full integration |
