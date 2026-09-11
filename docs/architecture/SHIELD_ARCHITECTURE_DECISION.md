# SHIELD_ARCHITECTURE_DECISION — REBUILD-001

**Decision: DO NOT CREATE `/shield` as a separate directory. Close the capability gap inside `rust-src/` (P0-2) instead.**

**HEAD:** `a480efb` · **Mode:** read-only audit · **Date:** 2026-09-10

---

## Answers (required format)

**SHIELD DECISION:** DO NOT CREATE

**REASON:** `/shield`'s only production-verified responsibility was a single DLL export — `validate_payload_safety([*]const u8, usize) -> bool` — loaded dynamically by `src/core/bridge_init.zig` as the "Tier-3 Memory Safety Shield". That responsibility is security-relevant and currently BROKEN (P0-2): the loader fail-opens (`return true`) when the DLL is missing, and the DLL cannot exist because `shield/` was deleted. However, restoring a whole second Rust crate would create a second Rust authority beside `rust-src/` (the ONE PEP), violating the no-duplicate-authority invariant. The correct repair is to move ~20 lines of payload-validation code into `rust-src/lib.rs` — the canonical security crate — and repoint the loader. One security crate, one security truth.

**RUST-SRC RESPONSIBILITY:** Final privileged authority: Ed25519 policy signature verification, PEP enforcement decisions (`aegis_pep_enforce`), rate-limit quota, SHA-256 hashing, federation TLS (stubs). Owns `aegis_pep.dll`.

**SHIELD RESPONSIBILITY (recovering):** Payload safety pre-validation (memory-safety screening of untrusted payloads before Zig-side processing). This is a *defensive screening* function, NOT enforcement. It belongs in the security crate because it is security logic, but it is not a second PEP — it advises; only the PEP decides enforcement.

**BUILD:** No `/shield` to build. `rust-src` already builds via `cargo build --release` → `aegis_pep.dll` (CI runs `cargo build/test --release` and it is green).

**TEST:** New requirement: `validate_payload_safety` gets a unit test inside `rust-src` (cargo test) plus the existing Zig-side contract test when the orphan graph is compiled. A standalone `/shield` would have needed its own CI job for zero unique logic — rejected.

**RUNTIME:** After repair: `aegis_pep.dll` exports both `aegis_pep_*` (PEP) and `validate_payload_safety` (shield). `bridge_init.initRustShield()` switches from `DynLib`-searching `sec_monitor.dll` at `target\release` + `shield\target\release` to loading the SAME `aegis_pep.dll` it already knows how to find, symbol `validate_payload_safety`. One DLL, one search path, no phantom `shield/target`.

**RELEASE:** `aegis_pep.dll` ships as today. No new artifact. `bridge_init.SHIELD_VERSION` should be removed or aliased to the PEP version (it currently hardcodes "0.1.0" claiming to mirror `shield/Cargo.toml`, which no longer exists — stale truth).

**SECURITY BOUNDARY:** Unchanged and strengthened: Zig may call `validate_payload_safety` (screening) and `aegis_pep_enforce` (decision) — both exported by the one Rust authority. All privileged enforcement still flows PEP → authorization → WFP. The fail-open must become fail-closed-configurable: default behavior and the risk must be made explicit (P0-2 note).

## The P0-2 fail-open, precisely

```zig
// src/core/bridge_init.zig (current)
pub fn validatePayloadSafety(data: [*]const u8, len: usize) bool {
    if (fn_validate_payload_safety) |f| return f(data, len);
    return true; // fail-open when Rust DLL not available  ← P0-2
}
```

With `shield/` deleted, `sec_monitor.dll` never loads, so Tier-3 screening is permanently bypassed AND silently (logged once as an error line at startup, then business as usual). Two acceptable repairs, in order of preference:

1. **Move screening into rust-src** (recommended): add `validate_payload_safety` to `rust-src/lib.rs`, retarget `bridge_init` to load it from `aegis_pep.dll`. Removes the dependency on a deleted crate entirely.
2. If Tier-3 screening is judged obsolete: delete the loader code path in a later cleanup phase and document the acceptance decision. NEVER leave it silently fail-open (current state).

## Why not CREATE /shield (explicit)

- It would duplicate the Rust security plane (`rust-src/` owns crypto, trust, PEP, authorization).
- Its historical crate had a version constant mirrored in `bridge_init.zig` and a `shield/target/release` search path — infrastructure for a directory that adds a second authority, not a capability.
- The single capability it held is a ~20-line function, naturally hosted in the existing security crate.
- SYSTEM_MAP's own note ("shield — minimal/placeholder") confirms it never earned an independent existence.
