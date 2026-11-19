# RB-010: Telemetry Export Setup

## Objective

Know which export surfaces exist on this host and use the live one.
The old revision described OTLP + Prometheus + syslog-CEF push, all
configured -- most of that was never built. This revision states what
is real.

## Status first

- REAL today: `scripts/aegis_metrics.py`, a standalone Prometheus
  exposition exporter reading the local evidence log, serving
  `http://127.0.0.1:9100/metrics`. Opt-in (nothing starts it; nothing
  listens on :9100 by default).
- REAL today: `python tools\aegisctl.py metrics` (live control-plane
  numbers: queue, stages, policy_ir mirror state).
- NOT BUILT: OTLP spansink, syslog-CEF push (`siem_endpoint`), any
  `[telemetry]` stanza in `configs/runtime.json` (check: no such keys).
  Do not configure endpoints for sinks that do not exist.

## Steps (Prometheus surface, the executable part)

1. **Start the exporter (foreground first)**
   ```bat
   python scripts\aegis_metrics.py
   ```
   - Serves `http://127.0.0.1:9100/metrics` until Ctrl+C. Localhost
     only; no auth -- do not expose the port off-host.

2. **Scrape and compare**
   - Scrape `:9100/metrics`, compare event totals against
     `python tools\aegisctl.py metrics` and `events count`.
   - Same source log, so totals must agree within scrape skew.

3. **Stop with Ctrl+C when done** (no installer, no service wrapper;
   scheduled/daemonized export is a future decision, not a fact).

## CEF strings (reference, not a sink)

- CEF export format strings live in `src/xdr/xdr_harden.zig`
  (unit-pinned). There is no CEF push running; delivery proof is
  RB-015 (lab, file-sink).

## Verification

- `:9100/metrics` serves while the exporter runs; totals agree with
  control-plane numbers.
- Stopped exporter = silent port (nothing retries, nothing queues).

## Rollback

- Ctrl+C. Nothing persists.

## Notes

- Severity mapping (shared with RB-008): critical=9, high=7,
  medium=5, low=3.
- A `[telemetry]` config stanza does nothing today; adding one is a
  feature request, not configuration.

## References

- RB-008 (formats), RB-015 (delivery proof, lab)
- `scripts/aegis_metrics.py --help`

## Production-sufficiency limits (current HEAD)

- `:9100/metrics` is **log-derived** (`logs/aegis_core.ndjson`), not the live
  control plane. It emits 8 series and does **not** expose `data_integrity`
  loss, `queue.stats` depth, or per-stage latency. The module docstring still
  lists legacy metric names that are not emitted; trust the 8 series in
  `generate_prometheus_metrics()`.
- It is opt-in and localhost-only. Stopping the process leaves no port, no
  queue, no retry. There is no service wrapper, no TSDB, and no retention or
  downsampling policy.
- No alerting exists. The only fail-closed thresholds are the soak
  `--loss-budget 3500` / `--shed-budget 20000` and `aegisctl readiness`.
- `go/aggregator /api/health` hardcodes `out_events=0` and `dropped=0`; use
  daemon `health.data_integrity` for loss truth.
- Counters are cumulative-since-start and reset on daemon restart; there is no
  in-process boot-id or restart counter.
- Full surface inventory and the source-vs-doc gap table:
  `docs/runbooks/RB-020-observability-manual.md`, section
  "Metrics sufficiency for production SRE".
