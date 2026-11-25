# MASTER AUDIT — AEGIS-002/014 scope consistency and README refactor (2026-11-25)

**TARGET HEAD:** `e260061fe8f47c85eedd22e9cf83a83022ad4e2c` (C1)
**BUILD SOURCE:** `43a8bcc02358076380fa938b0e5632870643d3c5` (unchanged)

## PATCH DECLARATION

```
PATCH-ID:             AEGIS-002-014-SCOPE-README
FLOW-ID:              scope claim -> README -> diagrams -> operations doc
TARGET HEAD:          C1 commit (e260061)
TARGET FILES:         README.md
                      docs/architecture/DIAGRAMS.md (new)
                      docs/operations/QUICK_START.md (new)
                      EVIDENCE_INDEX.json
TARGET SYMBOLS:       production-grade claim; Known limitations section;
                      build/verify command blocks; three architecture diagrams
IN-SCOPE:             Scope wording, limitation visibility, diagram set, moving detailed
                      build commands out of README
OUT-OF-SCOPE:         source, wire, rules, authority, host effects, release identity,
                      deletion of historical docs, test commands in README
CONTRACT IMPACT:      none
ABI IMPACT:           none
AUTHORITY IMPACT:     none
STATE IMPACT:         none (records only)
TEST IMPACT:          tests/docs + tests/release + doc checker + truth verify
EVIDENCE IMPACT:      one E1 evidence entry at build source 43a8bcc
```

## OLD FLOW -> NEW FLOW

- OLD: `production-grade contracts` at README:9 reads as an unqualified maturity claim.
  Known limitations sat at the end of a 775-line README. Detailed build commands and
  verification blocks were inline. No diagram set separated data flow from control flow
  or marked validation points.
- NEW: `production-oriented contracts`. A short Known limitations box appears near the
  top with a link to the full section. Detailed build/first-start commands moved to
  `docs/operations/QUICK_START.md`. Three diagrams added in `docs/architecture/DIAGRAMS.md`
  (component architecture, event lifecycle, trust boundary) with separate data/control
  edges and `V1/V2/V3` validation points.

## INVARIANT

- Production remains detection-only / observe-only; lab-only stages are labelled.
- No new claim of Windows E5, production qualification, MITRE mapping, replay
  re-execution, backpressure or zero loss.
- No file was deleted; historical records remain untouched.
- `docs/architecture/DIAGRAMS.md` points to existing schema/authority sources instead of
  duplicating them.

## VERIFICATION

| Check | Result |
|---|---|
| `python scripts/doc_checker.py` | 0 FAIL, 0 WARN, 23 total |
| `python -m pytest tests/docs tests/release -q` | 262 passed |
| `git diff --check` | clean |
| `python tools/truth.py verify` | TRUTH_VALID @ 43a8bcc |

## EVIDENCE LEVEL

E1 (documentation truth). No build, host or detection proof is claimed by this patch.

## ROLLBACK

Revert the patch commit. No source, build output or signed artifact changes.

## REMAINING RISK

- Diagram content is source-described, not a live host trace; the file states this.
- README still contains operator proof commands in the "Safe testing workflow" section;
  moving those would be a separate readability-only slice.

## OPEN BLOCKERS

None for this records-only patch.

## COMPLETION GATE

PASS when doc checker is 0/0, docs/release tests pass, `git diff --check` is clean and
truth remains TRUTH_VALID @ 43a8bcc. All four conditions met.
