============================================================
AEGIS MOUTH v3.0 - Deployment Guide
============================================================

FILES IN THIS PACKAGE:
------------------------------------------------------------
  windows_sec_monitor.rs   Main DEFCON enforcer (v3.0)
  Cargo.toml               Canonical build manifest (cargo only)
  Cargo.lock               Pinned dependencies
  build_mouth.bat          Build script (CMD-safe, drives cargo)
============================================================

RETIRED (EVT-107): aegis_mouth_tui.rs was never committed, so no build
may require it. run_mouth.bat never existed in this tree; run the
binary directly (see step 3).

DEPLOYMENT STEPS:

1. BUILD
   Run:  build_mouth.bat
   This runs `cargo build --release` and stages the binary into dist\:
   - dist\windows_sec_monitor.exe

2. RUN
   dist\windows_sec_monitor.exe --log logs\aegis_core.ndjson --refresh 1000
   Or:   dist\windows_sec_monitor.exe --log logs\aegis_core.ndjson --refresh 500

   (The default log tail is logs/aegis_core.ndjson. Older revisions of
   this guide named logs\anomalous.json; that name is retired.)

3. VERIFY
   dist\windows_sec_monitor.exe --version   (must print aegis-mouth 3.0.0)

============================================================
MOUTH v3.0 ROLE: "Guard + Voice"
- DEFCON focal point (border color = threat level)
- Active Mitigations panel (blocked IPs, terminated processes)
- Alert Feed: [Time] [Severity] [Source] -> [Action]
- NO system metrics (moved to NOSE)
============================================================
