# Step 37 — Real TLS / mTLS (Production Transport — Schannel or Approved TLS Stack)

**Status:** STUB (S2 framework — framework present; production TLS stack unverified; requires SChannel verification)
**Files:** `core/federation_tls.zig` (34,112 lines — framework present), `core/federation_tls_cli.zig` (6,507 lines — CLI framework), `core/federation_tls_config.json` (867 bytes — configuration framework)
**Production Subsystem:** `federation_tls.zig` (production framework; TLS framework present; production transport unverified per STEP 53 dependency — requires TLS handshake timeout/replay/revocation/rotation tests)

---

## Contract (Per ROADMAP STEP 37 — Real TLS / mTLS)

Production transport must use:
```
SChannel (Windows native TLS stack)
or
Approved production TLS stack (NOT mock TLS / NOT plaintext / NOT pass-through mock)
```

Tests required (before declaring PRODUCTION-VERIFIED):
- Server authentication
- Client authentication
- CA validation (SAN/CN verification)
- Expiry check
- Unknown CA rejection
- Revocation check
- Rotation verification
- Timeout and replay protection
- Replay attack prevention
- Timeout behavior

Forbidden in production:
- Plaintext communication
- Pass-through / mock TLS
- Unauthenticated transport

---

## Production Status

- TLS framework present (`core/federation_tls.zig` — 34,112 lines)
- TLS CLI framework present (`core/federation_tls_cli.zig` — 6,507 lines)
- TLS configuration framework present (`core/federation_tls_config.json` — 867 bytes)
- TLS handshake timeout framework present (`core/federation_tls.zig` — timeout mechanism present; timeout/replay/revocation/rotation tests missing — STEP 61 dependency — Final Regression requires TLS verification; STEP 52 dependency — rollback/recovery requires TLS transport preservation)
- TLS production verification: **STILL PENDING** — requires full TLS handshake tests (STEP 53 — Federation Production requires TLS authentication/replay/sequence/heartbeat; STEP 61 — Final Regression requires TLS regression; STEP 52 — Recovery requires TLS transport preservation)
- `.gitignore`: TLS test fixtures and mock certificates excluded; production config preserved

---

## References

- `core/federation_tls.zig` (production TLS framework — 34,112 lines)
- `core/federation_tls_cli.zig` (TLS CLI framework — 6,507 lines)
- `core/federation_tls_config.json` (TLS config — 867 bytes)
- `docs/ARCHITECTURE-TRUTH.md` (TLS: framework REAL; production TLS stack unverified — STEP 53 dependency: federation production requires TLS authentication/replay/sequence/heartbeat; STEP 37 dependency: TLS production verification requires all TLS handshake/replay/revocation/rotation/recovery tests)
- `docs/SHIELD-AUTHORITY.md` (Cross-language: TLS transport framework present; production TLS verification pending — STEP 53 dependency chain)
