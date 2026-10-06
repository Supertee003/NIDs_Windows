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

2. **Run the full TS suite** (76 tests: compiler, seal, exporter,
   cross-language contract, safety, Ed25519 sidecar):
   ```
   npm run test:all
   ```
   Expected: `pass 76, fail 0`. This includes the byte-for-byte
   exporter/fixture pin (`policy_ir_002.json`), the seal round-trip,
   and the Ed25519 sidecar suite (shape, round-trip, misuse,
   committed golden triple).

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
   "hash": "<full hash_hex>", "verified": false}` with the count and
   hash from step 5. (`verified` is the Ed25519 sidecar verdict from
   step 8 below; false is the normal unsigned state, not a failure.)

8. **(Optional) Ed25519 sidecar — observe-only** (POL-SIGN-079B).
   This proves the exact bytes the daemon mirrored, but changes no
   enforcement decision anywhere (key custody still open, ADR-0005):
   - Sign `configs/policy_ir.json` with YOUR Ed25519 tooling (the repo
     generates no keys and stores no private keys — operator-owned,
     offline). The signed message is the exact file bytes.
   - Write the sidecar next to it as `configs/policy_ir.sig.json`:
     `{"version": 1, "key_id": <u32 non-zero>,
     "ed25519_sig_hex": "<128 lowercase hex>",
     "ir_sha256_hex": "<64 lowercase hex, informational only>"}`.
     The signature is the trust root; the sha is a hint the daemon
     does not compare.
   - Pin the trust anchor: `AEGIS_POLICY_PUBKEY=<64 hex chars>` (the
     32-byte Ed25519 public key) in the daemon's environment.
     Absent anchor = unverified, never an error.
   - Restart the daemon. `metrics` shows `"verified": true` only when
     sidecar + anchor + bytes all agree; anything else stays false
     with a warn in the log. Enforcement posture unchanged either way.

9. **(Optional) Trust anchor file — reviewed keys, rotation window**
   (CUSTODY-081). The env anchor (step 8) is one key with no rotation
   story. For reviewed, rotatable custody:
   - Copy `configs/policy_trust.example.json` to
     `configs/policy_trust.json` (live file, gitignored — never commit
     real keys) and replace the all-zero placeholder with operator
     Ed25519 public keys: `{"version": 1, "keys": [{"key_id": 7,
     "pubkey_hex": "<64 hex>"}, ...]}`. The file holds PUBLIC keys
     only; private keys never touch the repo or the host.
   - Rotation = list old + new `key_id` side by side, switch signing
     to the new key, then remove the old entry. The daemon matches the
     sidecar's `key_id` and verifies against that anchor.
   - When present (and parseable), the file wins over
     `AEGIS_POLICY_PUBKEY`. A present-but-broken file warns and stays
     unverified — it never silently falls back to env.
   - Restart the daemon. `metrics.policy_ir.verified` behaves as in
     step 8. Enforcement posture unchanged either way.

10. **(Optional) Runtime PolicySet trust — opt-in enforcement**
    (TRUST-WIRE-082). The IR mirror above never gates enforcement;
    the runtime `policies.json` does (via `trusted` + PEP). To mark
    it trusted: `AEGIS_POLICY_ENFORCE_TRUSTED=1`, a sidecar at
    `configs/policies.sig.json` over the exact `policies.json` bytes
    (same v1 envelope as step 8), and trust anchors (policy_trust.json
    wins, else `AEGIS_POLICY_PUBKEY`). Valid envelope marks every
    loaded policy trusted; anything else behaves byte-identically to
    before (privileged actions keep escalating untrusted). Default
    (flag absent): zero behavior change. This is the staged cutover:
    observe + prove first, enforce only with operator keys.

## Verification

- `metrics` shows `policy_ir.loaded: true`, matching rule count and hash.
- `metrics` shows `policy_ir.verified: true` only with a matching
  sidecar + anchor (step 8); `false` is the normal unsigned state.
- `python tools/aegisctl.py snapshot` succeeds; enforcement posture
  unchanged (mirror is read-only by construction).
- TS suite green (`npm run test:all`: 76/76 at time of writing).

## Rollback

1. Delete (or restore the previous) `configs/policy_ir.json`.
2. Restart the daemon.
3. `metrics` shows `"policy_ir": {"loaded": false, ...}`; the runtime
   PolicySet from `policies.json` is untouched throughout — the mirror
   cannot break detection when removed.
