# AEGIS NIDS v5.0+ â€” Master Execution Roadmap (Fresh Build)

**Project**: AEGIS Network Intrusion Detection System for Windows
**Target OS**: Windows 10/11, Server 2019+
**Languages**: Zig 0.13+ (core), Rust 1.75+ (PEP), C (WFP/minifilter), Python 3.11+ (control plane)
**Working Directory (Dev)**: `/home/z/my-project/aegis_fresh/`
**Target Deployment**: `D:\NIDs_Windows`

## Two-Part Plan

### Part I â€” Core NIDS Foundation (I01â€“I21)
Foundation modules: contracts, capture, decoding, detection, policy, forensics.

| ID  | Module                                  | Language | Output Artifact                              |
|-----|-----------------------------------------|----------|----------------------------------------------|
| I01 | Repository Bootstrap & Build System     | Multi    | build.zig, CMakeLists.txt, Cargo.toml, .github/workflows/ci.yml |
| I02 | Canonical Event Schema                  | Zig      | src/contract/event.zig (IpcEvent 76 bytes)   |
| I03 | Runtime Manifest & Capability Declaration | Zig    | src/contract/runtime_manifest.zig            |
| I04 | Memory Pool & Lock-Free Queues          | Zig      | src/core/memory_pool.zig, src/core/ringbuf.zig |
| I05 | Logging & Diagnostics                    | Zig      | src/core/diagnostics.zig                     |
| I06 | Npcap Adapter (Real Capture)            | Zig      | src/capture/npcap_adapter.zig                |
| I07 | Packet Decoder (L2â€“L4)                  | Zig      | src/capture/packet_decoder.zig               |
| I08 | Flow Tracking Table                     | Zig      | src/capture/flow_table.zig                   |
| I09 | Protocol Parsers (HTTP/DNS/TLS/SMB/RDP)  | Zig      | src/capture/proto/                           |
| I10 | TCP Stream Reassembly                   | Zig      | src/capture/stream_reassembly.zig            |
| I11 | Signature Engine (Aho-Corasick)         | Zig      | src/detection/signature_engine.zig           |
| I12 | Statistical Anomaly Detector            | Zig      | src/detection/anomaly_detector.zig           |
| I13 | Protocol Anomaly Detector               | Zig      | src/detection/proto_anomaly.zig              |
| I14 | Event Correlator (Time-Window Rules)    | Zig      | src/detection/correlator.zig                 |
| I15 | Atomic Threat Tracker & Incident Model | Zig      | src/detection/threat_tracker.zig             |
| I16 | Policy IR (DSL Compiler)                | Zig      | src/policy/policy_ir.zig                      |
| I17 | Trust Store & Key Lifecycle             | Zig+Rust  | src/policy/trust_store.zig, src/pep/key_lifecycle.rs |
| I18 | PEP â€” Policy Enforcement Point          | Rust     | src/pep/pep_enforce.rs                       |
| I19 | Action Dispatcher (WFP/ETW)             | Zig+C    | src/policy/action_dispatcher.zig             |
| I20 | Forensic Record Pipeline                | Zig      | src/forensic/forensic_pipeline.zig           |
| I21 | Replay Engine (PCAP Replay)              | Zig      | src/forensic/replay_engine.zig               |

### Part II â€” Production Hardening (II01â€“II22)
Windows telemetry, reliability, federation, XDR, operations, release.

| ID    | Module                                    | Language | Output Artifact                              |
|-------|-------------------------------------------|----------|----------------------------------------------|
| II01  | ETW Real-time Source                      | Zig+C    | src/windows/etw_realtime.zig, src/windows/etw_native.c |
| II02  | File Integrity Monitor                    | Zig+C    | src/windows/fim.zig, src/windows/fim_native.c |
| II03  | Registry Monitor (Trie-based Rules)       | Zig      | src/windows/registry_monitor.zig             |
| II04  | Process & Thread Injection Detector       | Zig      | src/windows/injection_detector.zig           |
| II05  | WFP Block Action (Kernel Callout)         | C        | src/windows/aegis_wfp.c                       |
| II06  | Host Telemetry Aggregator                 | Zig      | src/windows/host_telemetry.zig                |
| II07  | Reliability Watchdog                      | Zig      | src/reliability/watchdog.zig                 |
| II08  | Security Self-Hardening                   | Zig+Py   | src/reliability/security_check.zig, tools/security_hardening.py |
| II09  | Performance Telemetry (Latency Histogram) | Zig      | src/reliability/latency_histogram.zig        |
| II10  | Config Schema Validator                   | Python   | tools/config_validator.py, configs/schema.json |
| II11  | Fault Injection Framework                 | Zig      | src/reliability/fault_injection.zig           |
| II12  | Federation Cluster Coordinator            | Zig      | src/federation/cluster_coord.zig             |
| II13  | Node Registry & Discovery                | Zig      | src/federation/node_registry.zig             |
| II14  | Federation Aggregator                     | Zig      | src/federation/aggregator.zig                |
| II15  | TLS/mTLS Transport                        | Rust     | src/federation/federation_tls.rs             |
| II16  | XDR Engine (Cross-Layer Correlation)      | Zig      | src/xdr/xdr_engine.zig                       |
| II17  | Control Plane CLI (aegisctl)              | Python   | tools/aegisctl.py                             |
| II18  | Installer (NSIS-based)                    | Python   | tools/installer.py, installer/aegis.nsi.tmpl |
| II19  | Backup & Recovery                         | Python   | tools/backup_recovery.py                      |
| II20  | CI/CD Pipeline (6 jobs)                   | YAML     | .github/workflows/ci.yml                      |
| II21  | Integration Test Suite (Golden Path)      | Python   | tests/test_golden_path.py                     |
| II22  | Release Engineering & Manifest            | JSON+Py  | tools/release_engineering.py, build_manifest.json |

## Build Outputs
- `zig build` â†’ `zig-out/bin/aegis_nids.exe` (core engine)
- `cargo build --release` â†’ `target/release/aegis_pep.dll` (PEP module)
- `cmake --build` â†’ `aegis_wfp.sys` (kernel callout driver, optional)
- `python tools/aegisctl.py` â†’ CLI control plane
- `python tools/installer.py` â†’ `aegis_setup.exe` (NSIS installer)
