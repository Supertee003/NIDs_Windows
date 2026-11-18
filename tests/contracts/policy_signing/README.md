# Policy Signing Golden Vectors

TS-signed fixture proving the author plane and the verify stack agree:
the signature here was produced by `ts_policy/src/ed25519.ts` equipment
and must verify under Zig `verifyViaRust` (Rust ring Ed25519).

## Files

- `policy_ir_golden.json` — the exact signed bytes.
- `policy_ir_golden.sig.json` — v1 sidecar (key_id 7).
- `policy_ir_golden.pub.hex` — trust anchor, 64 hex chars.

## Regeneration

Run `node tests/contracts/policy_signing/generate_policy_vectors.mjs`
from the repo root. The keypair is ephemeral (never persisted); only
public outputs are committed. Zig + TS consumers must pass on the new
files in the same patch (one schema, N codecs).
