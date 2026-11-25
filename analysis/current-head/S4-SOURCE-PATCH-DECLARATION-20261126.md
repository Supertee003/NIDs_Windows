# S4 Source Patch Declaration — versioned canonical policy bytes

- **PATCH-ID:** `S4-POLICY-CANONICAL-BYTES-001`
- **FLOW-ID:** `POLICY_AUTHORING -> CANONICAL_BYTES_V1 -> CROSS_LANGUAGE_VECTOR -> DIGEST EVIDENCE`
- **TARGET HEAD:** `bc753afb6b4842e2954761ee1c8dac101e0ec5b1` (records commit over build source `f1f89c183ee86410dbfdc748155dc3d22c086420`)
- **TARGET FILES:** new `shared/policy/policy_canonical_v1.md`, new
  `shared/vectors/policy_canonical_v1.json`, new
  `brain/policy_canonical_v1.py`, new
  `tools/generate_policy_canonical_vectors.py`, new
  `ts_policy/src/canonical_policy_bytes_v1.ts`, new
  `src/policy/policy_canonical_v1.zig`, new
  `rust-src/policy_canonical_v1.rs`, `ts_policy/src/index.ts`,
  `ts_policy/package.json`, `src/all_tests.zig`, `rust-src/lib.rs`, plus
  new per-language tests.
- **TARGET SYMBOLS:** `canonical_rule_bytes_v1`, `policy_rule_set_digest_v1`,
  `canonical_signature_bytes_v1`, `canonical_signature_digest_v1`,
  `canonicalRuleBytesV1`, `policyRuleSetDigestV1`,
  `canonicalSignatureBytesV1`, `canonicalSignatureDigestV1`,
  `canonicalRuleBytesV1` (Zig), `canonicalSignatureDigestV1` (Rust).
- **IN-SCOPE:** one explicit versioned byte layout for representation-B policy
  rules; fixed-width little-endian integers; length-prefixed UTF-8 strings with
  an explicit 256-byte cap; explicit enum ordinals; versioned rule-set digest
  and signed-policy envelope digest; one shared vector manifest consumed by
  Python, TypeScript, Zig and Rust tests.
- **OUT-OF-SCOPE:** silent replacement of legacy `canonicalRuleBytes`,
  `PolicyCompiler.compile()` hashing, `policy_signing.canonicalDigest`,
  `seal.ts::canonicalIRBytes`, T7 JSON-canonical validator, ADR-0005 exact-file
  Ed25519 sidecar, policy IR JSON bytes, rule IDs, action semantics, FFI ABI,
  enforcement authority, host effects and E3/E4/E5 claims.
- **CONTRACT IMPACT:** adds a new documented byte-stream contract. Existing
  wire/IR/sidecar contracts remain byte-identical. The legacy hash functions
  are explicitly labelled non-canonical in the new spec; no silent mutation.
- **ABI IMPACT:** none. No FFI signature, struct layout or wire field changes.
- **AUTHORITY IMPACT:** none. The encoder is a pure evidence/validation
  utility; it makes no policy decision and authorizes no host effect.
- **STATE IMPACT:** none. Generator writes only the committed vector artifact
  when explicitly invoked; tests are read-only.
- **TEST IMPACT:** Python, TypeScript, Zig and Rust tests read the same vector
  and pin exact bytes and digests, including delimiters, NUL, newline, Unicode,
  maximum string length and u64 values above `2^53-1`.
- **EVIDENCE IMPACT:** one new E2 evidence record. No E3/E4/E5, matrix,
  soak/install/signing or E6/E7 claim from this patch.
