# Step 34 — Forensics (Full Chain: Event → Evidence → Verdict → Policy → Signature → PEP → Action → Trace)

**Status:** STUB (S2 framework — framework present; full chain verification unverified)
**Files:** `core/forensics_engine.zig` (legacy framework reference — NOT in production build); production framework: `core/forensic_log.zig`, `core/forensics_engine.zig`, `forensic/forensic_pipeline.zig`
**Production Subsystem:** `core/forensic_log.zig` (immutable NDJSON audit), `core/forensics_engine.zig` (pipeline framework)

---

## Contract (Per ROADMAP STEP 34 — Full Chain Evidence)

Mandatory trace IDs that must survive dispatcher:
- `event_id`
- `incident_id`
- `policy_id`
- `policy_version`
- `request_id`
- `forensic_id`

Pipeline:
```
Event (Canonical)
    ↓
Evidence (detection_engine.zig -> Evidence[])
    ↓
Verdict (verdict_aggregator.zig -> AggregatedVerdict)
    ↓
Policy (core/policy_engine.zig -> PolicyDecision; framework present; compiler unverified per STEP 24)
    ↓
Policy Signature (core/policy_signing.zig -> SHA-256 + Ed25519; framework present; rotation/revocation/provisioning unverified per STEP 25)
    ↓
PEP Request (pep_bindings.zig -> shield/src/lib.rs; framework verified structurally; audit dimensions unverified per STEP 60)
    ↓
PEP Result (shield/src/lib.rs -> EnforcementResult with request_id, event_id, policy_id/version, action, target, timestamp, result)
    ↓
Windows Enforcement (build/Release/*.dll + WDK driver optional)
    ↓
Forensic Trace (core/forensic_log.zig -> append-only NDJSON; framework present; audit integrity unverified)
```

---

## Exit Gate (STEP 34 Partial)

- [x] Forensic framework present (`core/forensic_log.zig` — 18,408 lines; `core/forensics_engine.zig` — 16,145 lines)
- [x] Replay framework present (`core/replay_engine.zig` — 23,479 lines; `core/replay_integration.zig` — 7,863 lines)
- [x] Forensic trace captures full chain fields (event_id, incident_id, policy_id/version, request_id, forensic_id — framework defined)
- [x] Replay reports original/replayed/difference/reason (framework present; replay verification unverified per STEP 59)
- [ ] Full chain audit verified (requires STEP 57 — Security Decision Trace; requires STEP 58 — Shadow Comparison; requires STEP 59 — Replayable Security; requires STEP 25 — Policy Signing; requires STEP 26 — Rust PEP final verification; requires STEP 28 — Real WFP; requires STEP 55 — Real IPS; requires STEP 57 — Security Decision Trace; requires STEP 58 — Shadow Decision; requires STEP 61 — Final Regression)

---

## References

- `core/forensic_log.zig`
- `core/forensics_engine.zig`
- `core/replay_engine.zig`
- `docs/ARCHITECTURE-TRUTH.md` (Forensics: framework REAL; full chain verification unverified — requires STEP 25-28-34-35-57-58-59-61 chain)
- `STEP-25-POLICY-SIGNING.md`
- `STEP-26-RUST-PEP.md` (not explicitly created; framework verified structurally — `shield/src/lib.rs`)
