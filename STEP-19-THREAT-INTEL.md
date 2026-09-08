# Step 19 — Threat Intelligence (core/threat_intel.zig)

**Status:** S2 (Implemented — framework verified; feed normalization unverified)
**File:** `core/threat_intel.zig` (tracked; user's original dev; production framework)
**Production Subsystem:** `core/threat_intel.zig` (same file)

---

## Contract

Per `core/threat_intel.zig`:
- Normalizes: Go feed, Python feed, local feed, federation feed
- Evidence enrichment (NOT policy decision; NOT authorization)
- Must NOT modify policy directly (per authority invariants)

---

## Production Status

- Framework exists (`core/threat_intel.zig` — 41,678 lines)
- Integration framework: `core/threat_intel_integration.zig` (4,187 lines)
- Threat intel feeds defined but feed normalization unverified (STEP 19 requirement)
- **Not verified:** Remote node cannot override local authority (federation authority boundary — Step 36 dependency)

---

## References

- `core/threat_intel.zig`
- `core/threat_intel_integration.zig`
- `ARCHITECTURE-TRUTH.md` (threat intel framework noted as REAL; normalization unverified)
