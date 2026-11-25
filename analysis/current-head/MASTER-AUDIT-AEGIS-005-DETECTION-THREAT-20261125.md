# MASTER AUDIT — AEGIS-005 detection matrix and threat-model refresh (2026-11-25)

**TARGET HEAD:** `40b7aa3a79f3fb7fca888e8909c70929f643b369` (C4)
**BUILD SOURCE:** `43a8bcc02358076380fa938b0e5632870643d3c5` (unchanged)

## PATCH DECLARATION

```
PATCH-ID:             AEGIS-005-DETECTION-THREAT
FLOW-ID:              catalog source -> 23-row matrix -> threat model -> scope clarity
TARGET HEAD:          40b7aa3 (C4)
TARGET FILES:         docs/portfolio/DETECTION_MATRIX_CURRENT.md (new)
                      docs/portfolio/DETECTION_CATALOG.md
                      docs/DETECTION_VALIDATION.md
                      docs/SECURITY_THREAT_MODEL.md
                      README.md
                      EVIDENCE_INDEX.json
TARGET SYMBOLS:       generated 23-rule matrix; provenance banners; threat-model gap register
IN-SCOPE:             Generate the 23-row matrix from configs/Rules.json and
                      docs/DETECTION_VALIDATION.md; rebase live provenance to 43a8bcc;
                      record open source-observed gaps in the threat model
OUT-OF-SCOPE:         rule/wire/authority change, codec or rule implementation, host re-run,
                      soak, signing, new release/tag/key, MITRE mapping, "zero loss ever",
                      replay re-execution, active nonce/replay implementation
CONTRACT IMPACT:      none
ABI IMPACT:           none
AUTHORITY IMPACT:     none
STATE IMPACT:         none (records only)
TEST IMPACT:          tests/docs + tests/release + scope ratchet + evidence-index integrity
EVIDENCE IMPACT:      one E1 evidence entry at build source 43a8bcc
```

## OLD FLOW -> NEW FLOW

- OLD: `DETECTION_CATALOG.md` still called `a26c573` the current build source;
  `DETECTION_VALIDATION.md` also named `a26c573` as current. The 23-rule truth was spread across
  the catalog, validation table and matrix record, with no single generated current-source
  projection. The threat model described replay protection and release verification without
  stating the source-observed gaps at `43a8bcc`.
- NEW: `docs/portfolio/DETECTION_MATRIX_CURRENT.md` is generated from `configs/Rules.json` and
  `docs/DETECTION_VALIDATION.md` with all 23 rule IDs and exact catalog identity/action/pattern
  fields. Live provenance banners name `43a8bcc` while keeping `a26c573` explicitly HISTORICAL.
  The threat model now marks active nonce/replay as declared-not-enforced, names capture
  visibility gaps with source lines, clarifies one-signature release verification and adds an
  open-gaps register at `43a8bcc`.

## INVARIANT

- No rule, `match_pattern`, `regex_pattern`, wire layout, golden vector, authority or host effect
  changed; the matrix generator reads the catalog and validation table only.
- E5/E6 rows stay HISTORICAL at `f4cde3c`; narrow `43a8bcc` E3/E4/E5 proof is limited to the
  `-inject` lifecycle and exact deltas.
- Catalog 23/23, code-path 23/23, host-evaluable 22/23 and host-positive L4-only remain distinct.
- `Block` / `Drop` remain policy intent; production stays observe-only.
- The threat-model gaps are recorded as open; this patch does not implement or silently close them.
- Full current-head Windows E5 / kernel qualification remains `NOT_PROVEN`.

## VERIFICATION

| Check | Result |
|---|---|
| Matrix generator | 23 rules parsed from `configs/Rules.json`; 23 matching rows parsed from `docs/DETECTION_VALIDATION.md`; zero invented IDs |
| `python scripts/doc_checker.py` | 0 FAIL, 0 WARN, 23 total |
| `python -m pytest tests/docs tests/release -q` | 262 passed |
| `python -m pytest tests/release tests/docs tests/security/test_scope_ratchet.py tests/security/test_evidence_index_integrity.py -q` | 273 passed (`TMP`/`TEMP` redirected to `D:\aegis-tmp\tmp` because C: is near capacity) |
| `python scripts/check_summary.py --write` / `python scripts/check_summary.py` | SUMMARY_VALID |
| `git diff --check` | clean |
| `python tools/truth.py verify` | TRUTH_VALID @ 43a8bcc |

## EVIDENCE LEVEL

E1 (documentation truth generated from tracked source/catalog records and pinned by doc tests).
No build, host, detection or soak proof is claimed by this patch.

## ROLLBACK

Revert the patch commit. No source, rule, codec, vector, build output or signed artifact changes.

## REMAINING RISK

- The generated matrix relies on `docs/DETECTION_VALIDATION.md` for proof/E-level text. If that
  record changes, the projection must be regenerated; it is not an independent measurement.
- Threat-model gap rows are source-observed at `43a8bcc`; remediation advances build source and
  needs fresh E3/E4/E5 proof.
- Owner-attested host evidence remains outside a fresh clone.

## OPEN BLOCKERS

None for this records-only patch. VLAN/IPv6, collector shutdown, active IPC nonce/replay,
cross-language byte-vector ABI and full current-head E5 are later source/owner work.

## COMPLETION GATE

PASS when the generator emits 23/23 matched rows, doc checker is 0/0, tests pass, `git diff --check`
is clean and truth remains TRUTH_VALID @ 43a8bcc. All conditions met.
