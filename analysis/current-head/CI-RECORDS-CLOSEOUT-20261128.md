# CI reconciliation at records tip after the owner-delegated signature — 2026-11-28

**RECORD-ID:** `CI-RECORDS-CLOSEOUT-20261128`
**BUILD SOURCE:** `c01e8091995e3afb9e93e48ea3bd1d7cb6ae5cce`
**RECORDS HEAD AT READ TIME:** `f5c9b1a4ac498cc1767c90311ea15681d05ca7c0` (records-only after this patch; check `git rev-parse HEAD`)
**EVIDENCE LEVEL:** E1/E2 read-only CI-result reconciliation. Not E5/E6/E7 and not a soak result.

## 1. Why this record

The local solution-side checks and the owner-delegated signature were already
green, but the CI outcomes for the pushed records commits had not all been read.
This record consumes them verbatim from GitHub Actions and closes the remaining
repository-side bookkeeping item. No workflow, test, threshold or verdict was
changed.

## 2. Observed CI runs

| Commit | AEGIS CI | Host Regression (Phase T+K) | Meaning |
|---|---|---|---|
| `6de0184` (AEGIS-004b records closeout) | run `46060680923` — **failure** | run `46060680916` — success | Historical failure, see §3; resolved before the next records closeout |
| `e20f46f` (AEGIS-004a records rebaseline) | run `46056163773` — success | run `46056163713` — success | Both green |
| `9aef957` (AEGIS-008 records rebaseline) | run `46057895696` — success | run `46057895645` — success | Both green |
| `128c7f5` (AEGIS-003 records closeout / signed commit) | run `46063152181` — success | run `46063152110` — success | Both green; signed commit CI green |
| `f5c9b1a` (owner-delegated signature records commit) | run `46065310283` — success | run `46065310315` — success | Both green at the current records tip |

Source commits `3e7e591`, `3c78c96`, `473b3fe` and `c01e809`, and intermediate
rebaseline commits `9399a92`, `d282bbd8`, `3850beb`, `73b7210` and `bcd5498`,
were not pushed as standalone CI triggers. Their content is covered by the later
pushed records commits above, which contain the same source/build tree at the
time of each run. No CI PASS is claimed for a commit that was not actually run.

## 3. The one historical failure, diagnosed

`AEGIS CI` at `6de0184` failed in `Python Control Plane Tests`
(`tests/security/test_evidence_index_integrity.py::test_entry_ids_are_unique_and_levels_are_valid`):

```text
AssertionError: invalid evidence levels:
[('AEGIS-004B-V1-GATES-E2E3-20261128', 'E2 + narrow E3')]
1 failed, 1495 passed, 28 skipped, 18 deselected, 21 subtests passed in 314.00s
```

The `Cross-language CI Matrix` then failed only because its required
`python-tests` input was `failure`; every other required job was `success`.
The invalid composite level was a records defect, not a source or test failure.
It was corrected to the allowed level `E2` in the current `EVIDENCE_INDEX.json`,
with the `E2_count` rebaselined and `SUMMARY_VALID` re-proved locally. The
correction is visible in the green CI runs at `e20f46f`, `9aef957`, `128c7f5`
and `f5c9b1a`. No test was skipped, xfailed, guarded or relaxed to achieve this.

## 4. Completion gate and boundaries

- Repository-side CI reconciliation is **PASS**: all pushed records commits at
  and after `e20f46f` have both required workflows green; the single earlier
  failure is HISTORICAL and explained by the records-level fix above.
- This does **not** close `soak_24h`; the board remains **5/6 PASS, NOT
  SHIPPABLE** with `soak_24h` alone OPEN.
- CI green does not create E5/E6/E7, driver signing, a new release identity or
  a soak window. Full current-source Windows E5/kernel IDS qualification remains
  NOT_PROVEN.
- Soak remains the final owner-armed step; no host, service, driver, installed
  binary or finalizer was touched by this reconciliation.

## 5. Patch transaction declaration

| Field | Value |
|---|---|
| PATCH-ID / FLOW-ID | `CI-RECORDS-CLOSEOUT-20261128` / `GitHub Actions run -> read-only consume -> records truth surfaces` |
| TARGET HEAD | `f5c9b1a4ac498cc1767c90311ea15681d05ca7c0` |
| FINAL HEAD | the records commit created by this patch (`git rev-parse HEAD` after commit); build source remains `c01e809` |
| FILES CHANGED | this record, `EVIDENCE_INDEX.json`, `release/release-status.json`, `docs/START-HERE.md`, `docs/PATH-TO-COMPLETE.md` |
| OLD FLOW → NEW FLOW | CI outcomes unread / one historical failure un-attributed → explicit run IDs + failure cause + later green runs recorded |
| INVARIANT | No source, workflow, threshold, verdict, gate, signature, soak or host change; no fabricated CI PASS for unpushed commits |
| BUILD RESULT | No build; read-only `gh run list`, `gh run view`, `gh run view --log-failed` |
| TEST RESULT | `scripts/check_summary.py` SUMMARY_VALID; targeted release/doc-truth pytest previously 248 passed at `f5c9b1a`; no new source tests required for records-only patch |
| WINDOWS RESULT | Not applicable |
| EVIDENCE LEVEL / ARTIFACTS | E1/E2: this record plus `EVIDENCE_INDEX.json` and `release/release-status.json` |
| ROLLBACK | Revert this records-only patch; all CI facts remain externally verifiable by run ID |
