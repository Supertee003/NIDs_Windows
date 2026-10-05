# RB-011 — Author, Seal, Export, and Verify the TS Policy IR Mirror

## Objective

Take TypeScript-authored policy rules through compile → seal → export,
place the artifact where the daemon mirrors it, and prove the mirror
matches what was authored. Every command below was executed green while
writing this runbook.

## Prerequisites

- Node 20+, `ts_policy/node_modules` installed
- A current daemon binary (includes T3-TSIR-025 or later)
- Operator access to `configs/` (placement) and daemon restart

## Background (read once — it explains every limitation below)

- The TS plane is **authoring-only**: `compile()` (pure) → `exportIRJson()`
  (pure, `hash_hex` is the identity) → `seal()` (SHA-256 HMAC custody
  proof, NOT Ed25519 — real signing is a future Rust tier).
- The daemon loads `configs/policy_ir.json` **at startup only** into a
  **verify-only mirror** (`g_policy_ir`). It never replaces the runtime
  PolicySet and never touches enforcement authority.
- `policy.verify` on the control plane honestly refuses
  (`NOT_IMPLEMENTED`): there is no signed-envelope validator in the
  active loader yet. Do not mistake the mirror for enforcement trust.

## Steps

1. **Typecheck the authoring plane** (from repo root):
   ```
   cd ts_policy
   npm run typecheck
   ```
   Expected: exit 0, no output beyond the command line.

2. **Run the full TS suite** (71 tests: compiler, seal, exporter,
   cross-language contract, safety):
   ```
   npm run test:all
   ```
   Expected: `pass 71, fail 0`. This includes the byte-for-byte
   exporter/fixture pin (`policy_ir_002.json`) and the seal round-trip.

3. **Author and compile rules** with the TS API (`compile`, `makeRule`;
   see `ts_policy/src/compiler.ts` and the `policy_ir_002` construction
   in `ts_policy/tests/exporter.test.ts` for the proven pattern).
   Deterministic order is enforced by the compiler
   (priority DESC, specificity DESC, rule_id ASC).

4. **Seal for custody** with `seal()` (`ts_policy/src/seal.ts`):
   signer id (1–16 chars), non-negative `policy_version`, explicit
   `expiry`. Then `verifySeal()` round-trips locally
   (`VALID`/`TAMPERED`/`EXPIRED`/`ROLLBACK`). Keep the signer registry
   and the highest-accepted-version state — TS has neither.

5. **Export the mirror artifact** with `exportIRJson(result,
   result.canonical_hash_hex)` and write it to exactly
   `configs/policy_ir.json`. Record the printed `hash_hex` — it is the
   artifact's identity for step 7.

6. **Restart the daemon.** The mirror loads at startup only; there is
   no hot-reload for `policy_ir.json` (unlike `rules.reload`).

7. **Verify the mirror**:
   ```
   python tools/aegisctl.py metrics
   ```
   Expect `"policy_ir": {"loaded": true, "rules": <N>,
   "hash": "<full hash_hex>"}` with the count and hash from step 5.
   If `policy_ir` is absent entirely, the daemon binary predates the
   mirror — rebuild/restart, do not edit configs to compensate.

## Verification

- `metrics` shows `policy_ir.loaded: true`, matching rule count and hash.
- `python tools/aegisctl.py snapshot` succeeds; enforcement posture
  unchanged (mirror is read-only by construction).
- TS suite green (`npm run test:all`: 71/71 at time of writing).

## Rollback

1. Delete (or restore the previous) `configs/policy_ir.json`.
2. Restart the daemon.
3. `metrics` shows `"policy_ir": {"loaded": false, ...}`; the runtime
   PolicySet from `policies.json` is untouched throughout — the mirror
   cannot break detection when removed.
