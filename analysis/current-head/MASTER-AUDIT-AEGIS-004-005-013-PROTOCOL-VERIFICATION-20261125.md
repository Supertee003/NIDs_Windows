# MASTER AUDIT — AEGIS-004/005/013 protocol index and verification summary (2026-11-25)

**TARGET HEAD:** `fa7ce5d723cb6a9ef30c81f7a88514d3202f2ad3` (C3)
**BUILD SOURCE:** `43a8bcc02358076380fa938b0e5632870643d3c5` (unchanged)

## PATCH DECLARATION

```
PATCH-ID:             AEGIS-004-005-013-PROTOCOL-VERIFICATION
FLOW-ID:              codec facts -> protocol index -> recorded results -> verification summary
TARGET HEAD:          C3 commit (fa7ce5d)
TARGET FILES:         docs/protocol/INDEX.md (new)
                      docs/portfolio/VERIFICATION_SUMMARY.md (new)
                      EVIDENCE_INDEX.json
TARGET SYMBOLS:       protocol answer sheet; verification result table
IN-SCOPE:             Answer the nine protocol questions from current codec sources; present
                      a 3-5 minute verification summary with evidence and commit per row
OUT-OF-SCOPE:         wire layout change, golden vector change, codec implementation,
                      fresh build/host run, release identity, new PASS claims
CONTRACT IMPACT:      none (index only; source-of-truth order is stated)
ABI IMPACT:           none
AUTHORITY IMPACT:     none
STATE IMPACT:         none (records only)
TEST IMPACT:          tests/docs + tests/release + doc checker + truth verify
EVIDENCE IMPACT:      one E1 evidence entry at build source 43a8bcc
```

## OLD FLOW -> NEW FLOW

- OLD: protocol truth lived in `shared/protocol/wire_v*.md`, the frozen schema and the
  codec source; an auditor had to reconstruct answers. Verification numbers were
  scattered across README, RESULTS.md and EVIDENCE_INDEX.
- NEW: `docs/protocol/INDEX.md` answers header size, length prefix, version location,
  required/optional fields, endianness, maximum size, unknown-version handling and
  invalid-frame rejection with exact source lines, while explicitly deferring to the
  authoritative specs. `docs/portfolio/VERIFICATION_SUMMARY.md` gives a 3–5 minute
  table with recorded result, evidence and commit for each category.

## INVARIANT

- No wire layout, golden vector, rule, authority or host-effect change.
- No PASS entered without a recorded artifact; historical numbers are labelled as such.
- `674/674` is described as hash verification against one Ed25519 signature.
- Narrow E4/E5 at `43a8bcc` is not promoted to full Windows E5 or soak proof.

## VERIFICATION

| Check | Result |
|---|---|
| `python scripts/doc_checker.py` | 0 FAIL, 0 WARN, 23 total |
| `python -m pytest tests/docs tests/release -q` | 262 passed |
| `python -m pytest tests/release tests/docs tests/security/test_evidence_index_integrity.py -q` | First attempt: 3 failures from `OSError: [Errno 28] No space left on device` in pytest temp files (C: had ~248 MB free). Re-run with `TMP`/`TEMP` redirected to `D:\aegis-tmp\tmp`: **270 passed**. No source or tracked file changed for the space issue. |
| `git diff --check` | clean |
| `python tools/truth.py verify` | TRUTH_VALID @ 43a8bcc |

## EVIDENCE LEVEL

E1 (documentation truth derived from cited source lines and existing evidence records).
No fresh build, host or detection proof is claimed.

## ROLLBACK

Revert the patch commit. No source, codec, vector, build output or signed artifact changes.

## REMAINING RISK

- The index is a convenience layer; if a codec changes and the index is not updated,
  the source-of-truth order in the file resolves the conflict but the answer table
  would be stale. A future pin test could detect that drift.
- Verification summary rows deliberately cite different commits; readers must not
  merge them into a single "current run".

## OPEN BLOCKERS

None for this records-only patch.

## COMPLETION GATE

PASS when doc checker is 0/0, docs/release tests pass, diff is clean and truth is
TRUTH_VALID @ 43a8bcc. All four conditions met.
