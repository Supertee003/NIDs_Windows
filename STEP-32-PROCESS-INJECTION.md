# Step 32 — Process / Injection Detector (Real Process Telemetry + Evidence)

**Status:** STUB (S2 framework — framework verified; real telemetry and evidence production unverified)
**Files:** `core/injection_detector.zig` (legacy framework reference — NOT in production build; production framework: `windows/injection_detector.zig` — framework exists; evidence production unverified)
**Production Subsystem:** `windows/injection_detector.zig`

---

## Contract (Per ROADMAP STEP 32)

Real telemetry required:
- Process creation
- Process termination
- Image load (where required)
- Thread/injection evidence (injection detection framework present; evidence correlation unverified per STEP 18)

Pipeline:
```
Windows Process Event (C++ adapter: process creation/termination notifications)
    ↓
C ABI Boundary (process identity: PID, process name, parent PID)
    ↓
Zig Normalization (canonical_event.zig — immutable event with process identity)
    ↓
Injection Detector (core/injection_detector.zig — legacy; windows/injection_detector.zig — production)
    ↓
Evidence (core/forensics_engine.zig — framework present; process injection evidence unverified)
    ↓
Correlation (core/correlation_engine.zig — framework present; process + file + registry + network correlation unverified per STEP 18 dependency)
```

---

## Production Status

- Process telemetry adapter framework present (`core/injection_detector.zig` — legacy; `windows/injection_detector.zig` — production framework verified structurally)
- Process identity (PID + process name + parent PID) defined; image load tracking framework present; injection evidence framework present
- Correlation with process evidence (STEP 18 dependency — cross-source incident graph; 9 entity types: Host, User, Process, File, Flow, Session, IP, Domain, Pipe — unverified)
- Evidence production through forensics pipeline (STEP 34 dependency — full chain verification unverified)

---

## References

- `core/injection_detector.zig` (legacy framework reference — NOT in production build)
- `core/injection_detector_config.json` (configuration framework — unverified)
- `core/hids_engine.zig` (related host intrusion framework — framework verified; integration unverified)
- `docs/ARCHITECTURE-TRUTH.md` (Process/Injection: framework REAL; real telemetry + evidence production unverified — STEP 32 dependency)
