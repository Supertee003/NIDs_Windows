# ADR-0005: Policy Signing (Seal Format and Key Custody)

**Status:** Proposed (blocked on format + key-custody verdicts)
**Date:** 2026-10-06

## Context

Policy signing is three unconnected pieces. Investigation (code, not
opinion):

1. **Rust verifies, but nobody calls it.** `verify_policy_signature`
   (`rust-src/lib.rs:22-54`) is real ring Ed25519 (32-byte key,
   64-byte sig, tested: correct/wrong-key/wrong-data). In the current
   tree its only callers are its own unit tests — the enforcement
   path never invokes it (`signed_by = 0`, `policy_version = 0`).
2. **TypeScript cannot produce what Rust verifies.** `PolicyIR`
   carries `hash: u64` / `signature: u64` — first-8-byte prefixes
   (`ts_policy/src/types.ts:295-308`); `signature` is 0 until signed
   and no signing library is even depended on. An 8-byte prefix is a
   checksum hint, not a signature, and the fixed IR struct has nowhere
   to put 64 bytes.
3. **Zig gates but cannot verify.** `PepEnforcer.enforce` fail-closes
   privileged actions on untrusted policies
   (`src/policy/pep_bindings.zig:140-146`), but nothing can ever mark
   a policy trusted: `trust_store.zig` models key lifecycle
   (generate/lookup/revoke/rotate) with mock random material and has
   no sign/verify function at all.
4. **No shared envelope.** Author (TS) → mirror (Zig `policy_plane`,
   verify-only) → gate (Rust PEP) agree on no byte format for
   {canonical bytes, signature, key id}. ADR-0001 consequence 3
   ("real crypto, not FNV-1a") is still open.

## Proposal (recommendation, not decision)

- **Envelope:** sidecar file next to the IR JSON:
  `{ir_sha256: hex32, ed25519_sig: hex128, key_id: string,
  signed_at_ms: i64}` over the exact IR bytes the Zig mirror loads.
  Keep the `u64` IR fields as fast-path hints only (never trust).
- **Verify once, at load:** reuse the tested Rust primitive through a
  narrow FFI (`aegis_pep_verify_policy`) called by the Zig policy
  loader; success sets `trusted`. No new crypto code in Zig (its
  `std.crypto.sign` is the fallback if FFI is rejected).
- **Custody:** operator generates the keypair offline; the public key
  ships pinned in `configs/` (tracked, reviewed like Rules.json);
  the private key never touches the repo/host. Rotation = new keypair
  + overlapping `key_id` acceptance window, matching the rotation
  halves already modeled in `trust_store`.
- **Migration:** unsigned legacy policies keep loading untrusted
  (current fail-closed behavior unchanged); privileged actions on
  them keep escalating exactly as today.

## Rejected

- Trusting the `u64` prefix as a signature (forgeable hint).
- TS-side 64-byte sig stuffed into the fixed IR struct (breaks the
  cross-language struct contract; sidecar keeps it intact).
- Zig-side new Ed25519 code first (duplicates the tested Rust
  primitive; fallback only).

## Open owner questions

1. Envelope shape and field names (sidecar vs embedded)?
2. Verify in Rust-via-FFI (reuse) or Zig `std.crypto.sign` (no FFI)?
3. Key custody: who generates, where is the public key pinned,
   rotation window length?
4. Do unsigned legacy policies keep loading untrusted indefinitely,
   or is there a cutover that rejects them?

## Consequences

1. Nothing is wired by this ADR; `trusted` stays false everywhere.
2. Answers unlock: TS signing lib + exporter, sidecar writer, verify
   FFI + loader gating, golden vectors (all three tiers, same
   pattern as B2-AUTH-076).
3. Until then the T7 backlog lines stand.

## References

- `rust-src/lib.rs` (`verify_policy_signature`, `signed_by = 0`)
- `ts_policy/src/types.ts` (`PolicyIR`, `SealedPolicy`)
- `src/policy/pep_bindings.zig:140-146` (fail-closed gate)
- `src/policy/trust_store.zig` (lifecycle, mock material)
- `docs/runbooks/RB-011-policy-ir-mirror-workflow.md` (authoring flow)
- ADR-0001 consequence 3
