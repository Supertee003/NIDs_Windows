# AEGIS NIDS v5.0+ (Fresh Build)

Production-grade Network Intrusion Detection System for Windows.

## Architecture

| Layer        | Components                                                   |
|--------------|--------------------------------------------------------------|
| Capture      | Npcap adapter, packet decoder, flow table, L7 parsers, stream reassembly |
| Detection    | Aho-Corasick signatures, EWMA anomaly, protocol anomaly, multi-event correlation, atomic threat tracker |
| Policy       | Policy IR (DSL compiler), Trust Store + Key Lifecycle, Rust PEP, action dispatcher |
| Forensic     | 64 MiB ring buffer, PCAP replay engine |
| Host (Win)   | ETW real-time, FIM, registry monitor (trie), injection detector (T1055), WFP block, host telemetry aggregator |
| Reliability  | Watchdog, security self-hardening, latency histogram, fault injection |
| Federation   | Cluster coordinator, node registry, aggregator, TLS/mTLS |
| XDR          | Cross-layer correlation engine |
| Operations   | aegisctl CLI, NSIS installer, backup/recovery, CI/CD, integration tests, release engineering |

## Building (Windows)

Prerequisites:
- Zig 0.13.0+
- Rust 1.78+ (cargo)
- CMake 3.20+ and Visual Studio 2022 (MSVC)
- Npcap SDK (set `NPCAP_DIR` env var, or default `C:\Npcap`)

```powershell
# Build everything
zig build
cargo build --release
cmake -B build -S .
cmake --build build --config Release

# Run unit tests
zig build test
cargo test --release

# Generate installer
python tools/installer.py --generate
python tools/installer.py --package --output aegis_setup.exe
```

## Running

```powershell
# Install as Windows service (admin shell)
.\aegis_setup.exe

# Or run directly
.\zig-out\bin\aegis_nids.exe

# Control plane
python tools\aegisctl.py status
python tools\aegisctl.py rules list
python tools\aegisctl.py incidents list --severity alert
```

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full I01â€“I21 + II01â€“II22 module list.

## License

MIT â€” see [LICENSE.txt](LICENSE.txt)
