# MASTER AUDIT — AEGIS-003/006 health model and evidence provenance (2026-11-25)

**TARGET HEAD:** `6196680fc019556c7a609ce06a66b0a8b83132fe` (C2)
**BUILD SOURCE:** `43a8bcc02358076380fa938b0e5632870643d3c5` (unchanged)

## PATCH DECLARATION

```
PATCH-ID:             AEGIS-003-006-HEALTH-PROVENANCE
FLOW-ID:              health state -> documented fields -> evidence provenance -> scope clarity
TARGET HEAD:          C2 commit (6196680)
TARGET FILES:         docs/runtime/HEALTH_MODEL.md (new)
                      docs/evidence/PROVENANCE.md (new)
                      docs/SECURITY_THREAT_MODEL.md
                      EVIDENCE_INDEX.json
TARGET SYMBOLS:       health vocabulary mapping; reason/last_transition/impact/recovery_state;
                      provenance table; threat-model scope banner
IN-SCOPE:             Document actual health fields, mark unimplemented requested fields as gaps,
                      index evidence artifacts with their limits, align threat-model scope
OUT-OF-SCOPE:         source change, health field implementation, state rename, wire/rule/authority,
                      release identity, host proof re-run
CONTRACT IMPACT:      none
ABI IMPACT:           none
AUTHORITY IMPACT:     none
STATE IMPACT:         none (records only)
TEST IMPACT:          tests/docs + tests/release + doc checker + truth verify
EVIDENCE IMPACT:      one E1 evidence entry at build source 43a8bcc
```

## OLD FLOW -> NEW FLOW

- OLD: `RUNTIME_CONTRACT.md` exposed a health schema but no single page mapped the
  requested `HEALTHY/DEGRADED/FAILED/UNKNOWN` vocabulary or the requested fields.
  Evidence artifacts were scattered across EVIDENCE_INDEX, release trees, analysis
  records and local-only operator files. The threat-model banner still named `a26c573`.
- NEW: `docs/runtime/HEALTH_MODEL.md` maps `HEALTHY→RUNNING`, `DEGRADED→DEGRADED`,
  `FAILED→FAILED`, and states that `UNKNOWN` does not exist in production. It lists
  every health field actually emitted and marks `reason` as partial (worker-scoped)
  and `last_transition`, `impact`, `recovery_state`, `UNKNOWN` as **not implemented**.
  `docs/evidence/PROVENANCE.md` maps each artifact to what it proves and does not prove.

## INVARIANT

- No state is renamed in code; no field is claimed to exist unless a source line is cited.
- `last_transition`, `impact`, `recovery_state` and `UNKNOWN` are recorded as gaps,
  not silently invented. Implementing them would advance build source and require
  fresh E3/E4/E5 proof.
- The `DEGRADED` screenshot explanation in README is preserved: a real state is not retouched.
- Threat model keeps a HISTORICAL `a26c573` mention for the existing gate pin while
  recording the current source as `43a8bcc` and the narrow E4/E5 scope.
- Local `D:/aegis-tmp` transcripts are identified as local-only, unmodified evidence.

## VERIFICATION

| Check | Result |
|---|---|
| `python scripts/doc_checker.py` | 0 FAIL, 0 WARN, 23 total |
| `python -m pytest tests/docs tests/release -q` | 262 passed |
| `python tools/truth.py verify` | TRUTH_VALID @ 43a8bcc |
| `git diff --check` | clean |

## EVIDENCE LEVEL

E1 (documentation truth). No build, host or detection proof is claimed by this patch.

## ROLLBACK

Revert the patch commit. No source, build, health payload or signed artifact changes.

## REMAINING RISK

- `RUNTIME_CONTRACT.md:33-43` says "five-state lifecycle" but lists six states, while
  `state_machine.zig:6` has eight including `RECOVERING` and `STOPPING`. This is
  recorded as a documentation gap; it is not resolved by this records-only patch.
- Owner-attested `admin-evidence/` files remain outside a fresh clone.

## OPEN BLOCKERS

None for this records-only patch. Health field implementation belongs to a later
source slice with re-proof.

## COMPLETION GATE

PASS when doc checker is 0/0, docs/release tests pass, truth is TRUTH_VALID @ 43a8bcc
and the diff is clean. All four conditions met.
