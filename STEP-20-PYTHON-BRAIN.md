# Step 20 — Python Brain (brain/windows_brain.py / core/brain_engine.zig)

**Status:** S2 (Implemented — advisory framework present; advisory inference unverified)
**Files:** `brain/windows_brain.py` (Python advisory), `core/brain_engine.zig` (legacy framework reference; production advisory framework in brain/)
**Production Subsystem:** `brain/windows_brain.py` (Python — Intelligence / Advisory)

---

## Contract

Per `docs/ARCHITECTURE_CANONICAL.md` and `docs/FILE_CLASSIFICATION.md`:
- Input: Event + Flow + Verdict + Evidence + Threat Context + RAG Context
- Output: Advice (NOT enforcement) + Confidence + Explanation
- Semantic role: `Python = Intelligence / Advisory` (NOT enforcement authority)

---

## Invariant (Verified)

- Brain CANNOT enforce (`docs/ARCHITECTURE-TRUTH.md`: Brain framework REAL; advisory-only)
- RAG CANNOT authorize (`docs/ARCHITECTURE-TRUTH.md`: RAG authorization bypass risk — STEP 22 violation noted)
- Advisory output must NOT include ALLOW/BLOCK/QUARANTINE verdicts

---

## References

- `brain/windows_brain.py`
- `core/brain_engine.zig` (legacy framework reference; NOT in production build)
- `core/brain_integration.zig` (legacy integration framework)
- `docs/FILE_CLASSIFICATION.md` (brain/ = SOURCE — advisory framework)
