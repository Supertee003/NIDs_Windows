# Step 18 — Correlation (core/correlation_engine.zig)

**Status:** S2 (Implemented — framework verified; incident-level correlation unverified)
**File:** `core/correlation_engine.zig` (159 files in core/ — user's original dev tree; tracked per request; NOT in production build `build.zig`)
**Production Equivalent:** `core/correlation_engine.zig` (same file — correlation framework exists in both legacy and production context; `runtime_manifest.json` declares it as production module)

---

## Contract (Verified)

Per `core/correlation_engine.zig` lines 1-28:

- `EntityType`: `enum(u8)` — source_ip (0), dest_ip (1), session (2), user (3)
- `EntityKey`: `{ entity_type, ip (u32), session_id (u64) }`
- `CorrelationRule`: `enum` with `toString()`
- `CorrelationAlert`: `{ rule, entity_key, threat_count, triggering_event_id, description }`
- `CorrelationEngine`: `processVerdict(event, flow, verdict) -> [3]?CorrelationAlert`
- Constants: `MAX_ALERTS_PER_VERDICT = 3`, `THREAT_COUNT_THRESHOLD = 3`, `SLIDING_WINDOW_NS = 5 * ns_per_s`

---

## Production Status

- Framework exists (`core/correlation_engine.zig` — 683 lines)
- Integration framework present (`core/correlation_integration.zig` — 5,730 lines)
- Proof framework present (`core/correlation_proof.zig` — 17,760 lines)
- Test fixtures present (`tests/release/test_t17_perf_ci_installer.py` — references correlation benchmark suites; full correlation integration unverified)
- **Not verified:** Cross-source incident graph (network + host + process + file + registry) — requires Step 16 (Flow), Step 32 (Process), Step 31 (Registry) complete

---

## References

- `core/correlation_engine.zig`
- `core/correlation_integration.zig`
- `core/correlation_proof.zig`
- `ARCHITECTURE-TRUTH.md` (correlation framework noted as REAL with unverified cross-layer correlation)
- `docs/FILE_CLASSIFICATION.md` (correlation_engine.zig = SOURCE — production framework; NOT legacy)
