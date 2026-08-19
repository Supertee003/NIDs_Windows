============================================================
AEGIS MOUTH v3.0 - Deployment Guide
============================================================

FILES IN THIS PACKAGE:
------------------------------------------------------------
  windows_sec_monitor.rs   Main DEFCON enforcer (v3.0)
  aegis_mouth_tui.rs       TUI variant (v3.0 synced copy)
  build_mouth.bat          Build script (CMD-safe)
  run_mouth.bat            Run script (CMD-safe)
============================================================

DEPLOYMENT STEPS:

1. PLACE SOURCE FILES
   Copy these files to D:\NIds_Windows\mouth\:
   - windows_sec_monitor.rs
   - aegis_mouth_tui.rs

2. CLEAN OLD FILES (optional)
   Run cleanup_nose_mouth.bat first to delete v2.0 leftovers:
   - target\ (build cache)
   - src\ (old Cargo structure)
   - Cargo.toml, Cargo.lock, etc.

3. BUILD
   Run:  build_mouth.bat
   This compiles both .rs files into dist\:
   - dist\windows_sec_monitor.exe
   - dist\aegis_mouth_tui.exe

4. RUN
   Run:  run_mouth.bat
   Or:   run_mouth.bat 500   (custom refresh ms)
   
   Manual: dist\windows_sec_monitor.exe --log logs\anomalous.json --refresh 1000

============================================================
MOUTH v3.0 ROLE: "Guard + Voice"
- DEFCON focal point (border color = threat level)
- Active Mitigations panel (blocked IPs, terminated processes)
- Alert Feed: [Time] [Severity] [Source] -> [Action]
- NO system metrics (moved to NOSE)
============================================================
