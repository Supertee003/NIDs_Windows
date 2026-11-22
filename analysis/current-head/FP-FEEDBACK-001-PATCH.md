# FP-FEEDBACK-001 — Patch Record (E2)

## Declaration

| Field | Value |
|---|---|
| PATCH-ID | FP-FEEDBACK-001 |
| FLOW-ID | EVIDENCE-001 (advisory operator feedback) |
| TARGET HEAD | `183e095` |
| FINAL HEAD | `683ff20` |
| TARGET FILES | `tools/aegisctl/fp_feedback.py` (new), `tools/aegisctl.py`, `tools/aegisctl/config.py`, `tools/aegisctl/web_dashboard/app.py`, `tests/tools/test_aegisctl_mark_fp.py`, docs (2) |
| TARGET SYMBOLS | `FP_FEEDBACK_LOG`, `append_event`, `read_all`, `count`, `cmd_mark_fp`, `cmd_fp`, `fp_feedback` snapshot projection |
| IN-SCOPE | operator-marked false positives, local NDJSON feedback file, explicit advisory dashboard count |
| OUT-OF-SCOPE | detection suppression, auto-labelling, policy/rule mutation, control-pipe mutation, E5 |
| CONTRACT IMPACT | additive `snapshot.fp_feedback`; no CanonicalEvent wire change |
| ABI IMPACT | none |
| AUTHORITY IMPACT | advisory only; no detection or enforcement authority changes |
| STATE IMPACT | producer-owned file under `AEGIS_LOGS_DIR`; no in-memory counter |
| TEST IMPACT | 7 CLI tests + 2 dashboard tests |
| EVIDENCE IMPACT | E2 entry `FP-FEEDBACK-001-E2-20261119` |

## Old flow → New flow

`(no operator feedback path; FP count would have to be fabricated from detection counters)`
→
`aegisctl mark-fp <event_id> [--reason] → append one bounded escaped record to logs/fp_feedback.ndjson → re-read to verify → fp count/list + advisory dashboard KPI`

## Invariant

Every write targets `AEGIS_LOGS_DIR` (tmp_path in tests) via a dedicated module; `query_control` is never called by `mark-fp`. `event_id` must be a positive integer; reason is bounded and control characters are stripped. Duplicate marks are legitimate records. The count is labelled `source=local_log, advisory=true` and never feeds detection, policy, correlation or enforcement.

## Verification

- `python -m pytest tests/tools/test_aegisctl_mark_fp.py -q` 7 passed
- Targeted CLI/dashboard/gate set: 50 passed, 9 subtests passed
- Static pins: no `query_control` in the mark-fp path; no tracked-tree writes.

## Evidence level

E2. No E5 claim: no live operator feedback on the installed candidate.

## Rollback

Revert `683ff20`; remove `tools/aegisctl/fp_feedback.py`, the two CLI verbs, the config path and the dashboard projection.

## Remaining risk / blockers

- The feedback file is producer-owned and untracked; operators own rotation/archiving.
- No E5 host proof until a new signed candidate and a fresh owner-named soak window.

## Completion gate

Local-only advisory feedback, verified persistence, no suppression, no wire change — **PASS (E2)**.
