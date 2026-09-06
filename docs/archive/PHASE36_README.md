# AEGIS NIDS - Phase 36: ML/AI Flow Anomaly Detection

DevSecOps Tier 4 (Advanced Detection) - risk HIGH, mitigated by a hard
kill switch, additive-only design, and explainable verdicts.

## What this phase adds

| Deliverable        | Target path            | Purpose                                          |
|--------------------|------------------------|--------------------------------------------------|
| `ml_detector.zig`  | `core\ml_detector.zig` | Pure-Zig inference engine (26 unit tests)        |
| `ml_test_cli.zig`  | `core\ml_test_cli.zig` | Demo/verification CLI (5 scenarios, no Npcap)    |
| `ml_train.py`      | `scripts\ml_train.py`  | Offline trainer (pure stdlib, no numpy needed)   |
| `ml_model.json`    | `models\ml_model.json` | Pre-trained model (calibrated, FPR 0.0% @ 0.70)  |
| `PHASE36_README.md`| `PHASE36_README.md`    | This document                                    |

## DevSecOps position

| Aspect      | Value                                                        |
|-------------|--------------------------------------------------------------|
| Risk        | HIGH (new detection paradigm)                                |
| Mitigation  | Kill switch `enabled=false` by default; additive detector    |
| Rollback    | Set kill switch off / do not wire into pipeline / delete     |
| Enforcement | None. Detection only; blocking stays in the WFP driver       |
| FP budget   | Trainer prints Gate-4 check: model FPR < 5% at threshold     |

## Architecture

```
Npcap capture (Phase 32)                 MlDetector (Phase 36)
CanonicalEvent ------------------->  observe(ev)
  (frozen contract)                  FlowWindow (10 s window)
                                       - pkts/bytes counters
                                       - SYN/ACK/RST/FIN counts
                                       - unique dst ports / IPs
                                     flushWindow() every 10 s
                                       Features (8 dims)
                                       + per-src EWMA baseline (z)
                                       + logistic model score (p)
                                     classify() -> Verdict
                                       label + score + reasons[]
                                       -> SIEM / Web UI (Phase 38)
```

The detector does NOT import Npcap: it consumes CanonicalEvent values,
so it is fully testable on any machine. `ml_test_cli.exe` proves the
whole verdict chain without any capture dependency.

## Feature vector (8 flow features, per 10 s window)

| # | Feature            | Meaning                                   |
|---|--------------------|-------------------------------------------|
| 1 | pkts_per_sec       | Window packet rate                        |
| 2 | bytes_per_sec      | Window payload byte rate                  |
| 3 | syn_ratio          | SYN / TCP packets (flood/scan marker)     |
| 4 | rst_ratio          | RST / TCP packets (closed-port marker)    |
| 5 | unique_dst_ports   | Distinct contacted ports (scan marker)    |
| 6 | unique_dst_ips     | Distinct contacted hosts                  |
| 7 | inbound_ratio      | Inbound share (external targeting)        |
| 8 | mean_payload_len   | Avg payload (empty packets = suspicious)  |

## Verdict policy (explainable, layered)

1. **Kill switch** (`MlConfig.enabled`, default OFF): verdict is
   `DISABLED`, no window accumulation, no baseline updates.
2. **Model gate**: standardized 8-dim logistic score `p`.
   `p >= 0.70` (configurable) -> malicious; `p >= 0.35` -> suspicious.
3. **Signature overlays** (work even without a model):
   - >= 40 unique dst ports -> malicious; >= 20 -> suspicious
   - SYN ratio >= 0.8 at >= 50 pps -> malicious (SYN flood)
   - RST ratio >= 0.5 -> suspicious
4. **Baseline gate**: per-source EWMA packet-rate baseline
   (alpha 0.15, min 20 samples). `z >= 2x sigma_mult` AND `p >= 0.5`
   -> malicious; `z >= sigma_mult` (3.0) -> suspicious.

Every verdict carries up to 4 human-readable reasons, e.g.:

```
port-scan-50   pkts=50  pps= 10.2 ports=50  score=0.994 -> MALICIOUS
    - model score 0.99 >= threshold 0.70
    - port scan pattern: 50 unique dst ports
```

## Model JSON schema (v1)

```json
{
  "version": 1,
  "name": "aegis-flow-anomaly-v1",
  "trained_at": "2026-09-05T15:10:24Z",
  "features": [8 names - must match ml_detector.zig FEATURE_NAMES],
  "mean": [8], "std": [8],
  "weights": [8], "bias": 0.21,
  "confidence_threshold": 0.70,
  "metrics": {"accuracy": .., "precision": .., "recall": .., "f1": .., "samples": ..}
}
```

Validation at load time: version must be 1, every std > 0,
0 < threshold < 1. Invalid models are rejected (old model kept).

## Quick start

```powershell
# 1) Deploy (from D:\NIDs_Windows)
powershell -ExecutionPolicy Bypass -File .\phase36_deploy.ps1

# 2) Verify the shipped pre-trained model
.\ml_test_cli.exe demo models\ml_model.json     # expect 5/5 PASS
.\ml_test_cli.exe model models\ml_model.json    # print model summary

# 3) Re-train offline (optional, pure stdlib Python 3.8+)
python scripts\ml_train.py --out models\ml_model.json --seed 42

# 4) Re-train on REAL flow exports when available
#    CSV header: label,pkts_per_sec,bytes_per_sec,syn_ratio,rst_ratio,
#                unique_dst_ports,unique_dst_ips,inbound_ratio,mean_payload_len
python scripts\ml_train.py --csv my_flows.csv --out models\ml_model.json
```

## Zig integration sketch (capture loop)

```zig
const ml = @import("ml_detector.zig");

// once, at startup:
try ml.init(allocator, .{ .enabled = true, .confidence_threshold = 0.70 });
if (ml.instance()) |det| {
    try det.loadModelJson(model_json_bytes); // models/ml_model.json
}

// in the capture poll loop (Phase 32 npcap_capture.zig):
for (events) |ev| {
    ml.instance().?.observe(.{
        .timestamp_ns = ev.timestamp_ns,
        .src_ip = ev.src_ip,
        .dst_ip = ev.dst_ip,
        .src_port = ev.src_port,
        .dst_port = ev.dst_port,
        .protocol = ev.protocol,
        .tcp_flags = ev.tcp_flags,
        .payload_len = ev.payload_len,
        .direction = switch (ev.direction) {
            .inbound => .inbound,
            .outbound => .outbound,
            else => .unknown,
        },
    });
}
// every 10 s (timer in the loop):
if (ml.instance()) |det| {
    if (det.flushWindow()) |v| {
        if (v.label == .malicious) forwardToPipeline(v);
    }
}
```

## Tuning knobs (MlConfig)

| Knob                   | Default | Effect                                        |
|------------------------|---------|-----------------------------------------------|
| enabled                | false   | KILL SWITCH - master on/off                   |
| confidence_threshold   | 0.70    | Model probability for malicious               |
| baseline_sigma_mult    | 3.0     | Sigma gate for rate deviation                 |
| ewma_alpha             | 0.15    | Baseline smoothing (higher = adapt faster)    |
| min_baseline_samples   | 20      | Samples before z-scores are trusted           |
| window_secs            | 10.0    | Classification window length                  |
| max_keys               | 4096    | Baseline store bound (bounded memory)         |

## Verification checklist (host, no Npcap required)

- [x] `zig test core\ml_detector.zig` -> All 26 tests passed
- [x] `zig build-exe core\ml_test_cli.zig -lc` -> clean build
- [x] `.\ml_test_cli.exe demo models\ml_model.json` -> 5/5 scenarios PASS
- [x] `.\ml_test_cli.exe model models\ml_model.json` -> metrics printed
- [x] `python scripts\ml_train.py` reproduces a calibrated model (FPR < 5%)
- [ ] Wire into nids_capture.zig pipeline (follow-up integration step)

## Phase 36 shipped model metrics (synthetic-v1, seed 42)

- test: acc 0.994, precision 1.000, recall 0.987, f1 0.994, n=960
- Gate-4 FPR check: 0.0% (< 5% target)
- Weight profile: syn_ratio +1.24, mean_payload_len -1.32,
  pkts_per_sec +0.86, rst_ratio +0.80 (attacks are fast, empty-payload,
  SYN/RST heavy - matches intuition)

NOTE: shipped model is trained on SYNTHETIC windows for pipeline
verification. Retrain with `--csv` using real flow exports from your
network before relying on model-only verdicts; signature overlays
(port scan / SYN flood / RST) and the baseline gate are data-independent.
