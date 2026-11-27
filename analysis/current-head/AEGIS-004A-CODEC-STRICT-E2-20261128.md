# AEGIS-004a — strict v3 provenance tuple and exact legacy WEV1 length (E2)

**PATCH-ID:** `AEGIS-004-CODEC-STRICT-01a`  
**FLOW-ID:** canonical frame → decode/validate → reject counter → evidence  
**TARGET HEAD:** `0a1c101c4c75c2cfa3ef75c931eda273a3764aea`  
**FINAL SOURCE COMMIT:** `3e7e5918b74afc26a350270811aea74499003637`  
**RECORDS HEAD:** see `git rev-parse HEAD` (records-only after the source commit)  
**OWNER DECISION:** option B in `docs/SOURCE-SLICE-DECISIONS.md` — execute on main with full rebaseline.

## 1. Patch declaration

| Field | Value |
|---|---|
| Target files | `src/contract/wire_event.zig`; `nose/canonical.go`; `shared/wire/wire_codec.h`; `shared/wire/wire_codec.py`; `brain/canonical_event.py`; Zig/Go/Python/brain/C++ reject tests |
| Target symbols | `deserializeEvent`, `V3Envelope.Validate`, `aegis_v3_envelope_valid`, `validate_v3_envelope` |
| In scope | exact legacy WEV1 frame length (no ignored trailing bytes); complete four-field provenance tuple when `V3_FLAG_PROVENANCE_VALID` is set, in Zig/Go/C++/Python/brain |
| Out of scope | wire layout, struct fields, ABI, policy bytes, authority, verdict fields, host action, soak, gate thresholds |
| Contract impact | aligns all codecs to the existing `shared/protocol/wire_v3.md:69-73` rule; no new contract |
| ABI impact | none |
| Authority impact | none — Zig remains detection authority, Go acquisition only |
| State impact | none |
| Test impact | Zig unit, Go unit, Python reference + brain unit, C++ reference harness |
| Evidence impact | E2 only; no E3/E4/E5/E6/E7 promotion |

## 2. Old flow → new flow

- **Legacy WEV1:** `buf.len >= header + payload` accepted a frame with trailing bytes → now `buf.len == header + payload`; tests pass exact slices and a new test pins trailing-byte rejection.
- **Provenance:** Go/C++/Python/brain checked only the *negative* rule (fields must be zero when the flag is clear) and accepted a partial tuple when the flag was set → now each has the Zig-equivalent positive rule (all four fields nonzero when the flag is set).

**Invariant:** no valid frame changes meaning; only previously accepted malformed frames are now rejected. No golden vector was regenerated and no byte layout changed.

## 3. Real verification

| Check | Result |
|---|---|
| `zig test src/contract/wire_event.zig` | **65/65 passed** |
| `zig build test` | exit 0 |
| `cd nose && go test ./...` | `ok aegis-nose` |
| `cd nose && go vet ./...` | exit 0 |
| `pytest tests/contracts/test_payload_envelope_v3.py tests/brain/test_canonical_event_v3.py -q` | **37 passed** |
| C++ `wire_codec_v3_cpp_check` (g++ -std=c++17 -Wall -Wextra) | **PASS** |
| `python tools/rebuild_truth.py` | `valid: true`, source commit `3e7e591` |
| `python tools/release_engineering.py --refresh-digests` | 691 artifacts, 5 digests updated, verify OK at `3e7e591` |
| `python tools/final_audit.py --check` with owner anchor | **NOT SHIPPABLE (2/6 gates open)** — `release_signature`, `soak_24h` |

The broader suite initially showed four failures while source files were uncommitted: three `fresh_deploy` plan tests aborted at preflight and one digest-drift test saw the uncommitted files. After committing the source and re-recording digests on a clean tree, those are expected intermediate states, not logic regressions. No test was skipped, xfailed or relaxed.

## 4. Honest gate consequence (owner option B)

Moving the build source off `aa3b7b0` means:

- the owner-approved signature at `6c94b47` still verifies cryptographically but no longer contains the current runtime → `release_signature` **OPEN** (`final_audit.py:434-438`);
- all narrow E5/E6 records at `aa3b7b0` are **HISTORICAL** relative to `3e7e591`;
- the board goes from 5/6 to **4/6 PASS, NOT SHIPPABLE**; `soak_24h` remains OPEN.

No waiver, threshold change or new release identity was created. A new signature over a tree containing `3e7e591` must be owner-authorized externally; the private key is not in chat or the tree.

## 5. Rollback / remaining risk / open blockers

- **Rollback:** revert source commit `3e7e591`, then re-run `tools/rebuild_truth.py` and `tools/release_engineering.py --refresh-digests` to return the board to 5/6 at `aa3b7b0`.
- **Remaining risk:** the new provenance rule could reject a legitimate zero-valued field from a future producer; the live Nose producer always emits a complete tuple, and Zig ingress already enforced this, so this is parity, not a new policy.
- **Open blockers:** owner re-signature; fresh current-source soak; the still-deferred AEGIS-004b (v1 field gates, short-write seam), AEGIS-008 sensor E2 and AEGIS-003 additive health fields; frozen #47/#50 kernel work.
- **Completion gate:** E2 PASS for this transaction only. Not a release, not E5/E6/E7, not shippable.
