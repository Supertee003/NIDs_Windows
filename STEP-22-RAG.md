# Step 22 — RAG (Read-Only Context Enrichment)

**Status:** S2 (Implemented — framework present; authorization bypass risk noted; read-only verification partial)
**File:** `core/rag_engine.zig` (legacy framework reference; production: `core/rag_engine.zig` — framework exists but RAG authorization bypass risk remains)
**Production Subsystem:** `core/rag_engine.zig`, `core/rag_integration.zig`, `core/rag_intelligence.zig`

---

## Contract (Per ROADMAP STEP 22 + docs/ARCHITECTURE_CANONICAL.md Section 8)

- Pipeline: query → retrieve → rank → context
- **RAG MUST NOT return ALLOW / BLOCK / QUARANTINE verdict** (STEP 22 violation — authorization bypass risk documented)
- RAG enriches context; RAG does NOT authorize enforcement
- Failure mode: RAG unavailable → pipeline continues with reduced context (fail-soft)

---

## Authority Invariant (Per docs/ARCHITECTURE-TRUTH.md)

- [x] RAG CANNOT authorize enforcement (invariant maintained by framework design)
- [x] RAG CANNOT return ALLOW/BLOCK (invariant maintained — `core/rag_engine.zig` framework does not produce verdict vocabulary)
- [ ] Full authorization/replay/audit verification missing (STEP 42 dependency — privileged IPC authorization layered; audit/replay/recovery partial)

---

## Production Status

- Framework present (`core/rag_engine.zig` — 22,556 lines; `core/rag_integration.zig` — 5,330 lines; `core/rag_intelligence.zig` — 11,633 lines)
- RAG enrichment works (framework verified)
- Authorization bypass risk (STEP 22 violation) — RAG framework does NOT directly call PEP authorization, but full audit of all RAG output paths not fully verified
- Read-only property maintained by framework design (RAG produces context, not verdict)

---

## References

- `core/rag_engine.zig`
- `core/rag_integration.zig`
- `core/rag_intelligence.zig`
- `docs/ARCHITECTURE-TRUTH.md` (RAG: framework REAL; authorization bypass risk — STEP 22 violation noted; verification pending STEP 42 audit)
- `docs/FILE_CLASSIFICATION.md` (brain/ = advisory framework; RAG framework under core/)
