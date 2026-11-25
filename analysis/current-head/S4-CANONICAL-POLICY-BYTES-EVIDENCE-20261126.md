# S4 Canonical Policy Bytes Evidence — 2026-11-26

## Patch transaction

- **PATCH-ID:** `S4-POLICY-CANONICAL-BYTES-001`
- **FLOW-ID:** `POLICY_AUTHORING -> CANONICAL_BYTES_V1 -> CROSS_LANGUAGE_VECTOR -> DIGEST EVIDENCE`
- **TARGET HEAD:** `bc753afb6b4842e2954761ee1c8dac101e0ec5b1` (records commit over build source `f1f89c1`)
- **SOURCE COMMITS:**
  - `2673bd2486678992b17799ad5990b4139d0d5b1c` — `feat(policy): add versioned canonical policy bytes v1 (S4)`
  - `4dd33936909de1314099652a7523e52c40bb2c44` — `test(policy): register S4 canonical byte encoder as a visible brain seam`
- **FINAL BUILD SOURCE:** `4dd33936909de1314099652a7523e52c40bb2c44`
- **EVIDENCE LEVEL:** `PASS_E2` (unit + pure cross-language byte tests only)

## Old flow -> new flow

**Old:** four incompatible policy byte streams existed with no shared versioned
contract: `ts_policy/src/compiler.ts::canonicalRuleBytes` (`\x1f`-joined text),
`src/policy/policy_plane.zig` compiler hash (raw struct bytes),
`policy_signing.canonicalDigest` (LE header + pointer-bearing struct bytes),
`ts_policy/src/seal.ts::canonicalIRBytes` (newline/`|`/`=`-joined text), and a
JSON-canonical T7 validator. Cross-language byte equality could not be proven
from one shared manifest.

**New:** an additive `POLICY_CANONICAL_BYTES_V1` contract defines fixed-width LE
`PC01RULE` / `PC01SETS` / `PC01SIGN` pre-images with length-prefixed UTF-8
strings. One producer-owned vector manifest is consumed read-only by Python,
TypeScript, Zig and Rust encoders; exact rule bytes, rule-set digests and
signed-policy digests are pinned in all four languages.

## Invariant

This format carries evidence only. It changes no wire layout, FFI ABI, rule ID,
action semantic, policy decision, PEP authority or host effect. The legacy byte
streams and the ADR-0005 exact-file Ed25519 sidecar remain byte-identical;
migration of published hashes/signatures is an explicit future change.

## Files changed

`brain/policy_canonical_v1.py`, `tools/generate_policy_canonical_vectors.py`,
`shared/policy/policy_canonical_v1.md`,
`shared/vectors/policy_canonical_v1.json`,
`ts_policy/src/canonical_policy_bytes_v1.ts`,
`ts_policy/tests/canonical_policy_bytes_v1.test.ts`,
`src/policy/policy_canonical_v1.zig`,
`src/tests/policy/policy_canonical_v1.zig`,
`rust-src/policy_canonical_v1.rs`, `rust-src/lib.rs`, `src/all_tests.zig`,
`build.zig`, `ts_policy/src/index.ts`, `ts_policy/package.json`,
`tests/policy_signing/test_canonical_policy_bytes_v1.py`,
`tests/brain/test_seam_disposition.py`, `CONTRACT_MAP.json`, plus explicit
non-canonical labels in legacy comment sites.

## Verification actually run

| Command | Result |
|---|---|
| `python -m py_compile brain/policy_canonical_v1.py tools/generate_policy_canonical_vectors.py` | exit 0 |
| `python tools/generate_policy_canonical_vectors.py --write` | `vector_sha256=5012763e91c8e9b24a736c0826210510cdc9791451296e6c121439910c4d67c6; cases=4` |
| `python -m pytest tests/policy_signing/test_canonical_policy_bytes_v1.py -q` | `6 passed` |
| `cd ts_policy && npm run typecheck` | exit 0 |
| `cd ts_policy && npm run test:all` | `82 passed, 0 failed` |
| `cargo test --release policy_canonical_v1` | `2 passed, 0 failed` |
| `zig build --cache-dir D:\aegis-tmp\s4_zig_cache --global-cache-dir D:\aegis-tmp\s4_zig_global test` | exit 0 |
| `zig build` (same caches) | exit 0 |
| `python -m pytest tests/brain/test_seam_disposition.py -q` | `3 passed` |
| `python tools/rebuild_truth.py` | exit 0 |
| `python tools/truth.py verify` | `TRUTH_VALID` at build source `4dd3393` |
| `python tools/evidence_debt.py` | to be recorded below |
| `python scripts/check_summary.py` | to be recorded below |
| `python scripts/doc_checker.py` | to be recorded below |
| `python -m pytest -q -p no:cacheprovider tests/docs tests/release` | to be recorded below |
| `python -m pytest -q -p no:cacheprovider -m "not host_live"` | to be recorded below |
| `python tools/final_audit.py --release-check` | to be recorded below |
| `python tools/release_engineering.py --verify` | to be recorded below |

Logs: `D:\aegis-tmp\s4_pytest.log`, `D:\aegis-tmp\s4_tsc.log`,
`D:\aegis-tmp\s4_ts_tests.log`, `D:\aegis-tmp\s4_zig5.log`,
`D:\aegis-tmp\s4_zig_build.log`, `D:\aegis-tmp\s4_cargo2.log`,
`D:\aegis-tmp\s4_truth_rebuild2.log`, `D:\aegis-tmp\s4_truth_verify2.log`,
`D:\aegis-tmp\s4_pytest_nohost.log`, `D:\aegis-tmp\s4_final_audit.log`.

### Pin coverage

- Shared vectors cover empty/minimal rules, `\x1f`/NUL/newline/Unicode strings,
  the exact 256-byte string cap, `u64 = 2^53`, `u64 = 2^64-1`, multi-rule
  ordering, rule-set digest and signed-policy digest with a large `expiry_ms`.
- Each language rejects non-representable inputs (string over 256 bytes,
  ordinal over range, `u64` overflow) rather than silently coercing.
- The Python brain module is registered as a visible seam-only module, so an
  accidental production wiring (or an unregistered new brain module) fails
  `tests/brain/test_seam_disposition.py`.

## Limitations and open proof

- No E3/E4/E5, host, matrix, soak, install, signing or E6/E7 claim is made.
- The four legacy byte streams remain in production use; this patch does not
  migrate published hashes or signatures to V1.
- The encoder is not consumed by the daemon, PEP, compiler or signature
  producer; it is a pure validation/evidence utility.
- The current-source release check remains honestly NOT SHIPPABLE because
  `release_signature` and `soak_24h` predate the runtime source. The immutable
  `v1.1` / `466a226` / `a53eda8` release identity and its historical 6/6 result
  are unchanged.
- Full current-head Windows E5 / kernel IDS qualification remains NOT_PROVEN;
  the 23-rule matrix was last measured at `f4cde3c`.

## Rollback

Revert source commits `4dd3393` and `2673bd2`; then rebaseline machine maps
and re-record digests at the restored build source. The vector producer writes
only the committed `shared/vectors/policy_canonical_v1.json` and only under an
explicit `--write` flag; tests never rewrite tree state.

## Completion gate

`PASS_E2` for the source-level canonical-byte contract and cross-language byte
equality only. Policy migration, E3/E4/E5, matrix, soak/install/signing and
E6/E7 stay OPEN and are not implied by this record.
