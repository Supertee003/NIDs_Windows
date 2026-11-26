# Evidence index — reader's guide

The registry is [`EVIDENCE_INDEX.json`](../../EVIDENCE_INDEX.json) at the
repository root. This directory exists so evidence-balance notes have a stable
home; it adds no new evidence and changes no claim.

## Reading rules

1. An entry's `head_sha` is the source commit at which its result was recorded.
   Under ADR-0008 a records-only commit does not move the build source. If the
   recorded source is not the current build source, treat the entry as
   HISTORICAL even when its `result` says PASS.
2. `E5_with_artifact_count` counts truthy pointers, not openable files.
   Use `E5_with_resolvable_artifact_count` and
   `E5_with_unresolvable_artifact_count` to see what this worktree can actually
   open. Unresolvable pointers must carry `artifact_status` plus either an
   `artifact_locator` (historical operator archive) or an
   `artifact_status_basis` (missing).
3. A PASS in `known_gaps` means `CLOSED_AT_RECORDED_HEAD` unless the status is
   plain `CLOSED`. A voided soak window is not a PASS.
4. No E5/E6 claim inherits across a build-source change. Re-proof at the new
   source or keep the older claim explicitly HISTORICAL. The narrow current-source
   `-inject` re-proof is recorded in
   [`MASTER-AUDIT-P8-I44-CURRENT-SOURCE-20261125.md`](../../analysis/current-head/MASTER-AUDIT-P8-I44-CURRENT-SOURCE-20261125.md).
5. Release identity remains `v1.1` / signed candidate `466a226` / build source
   `a53eda8` with six fail-closed gates. No entry in this index re-opens or
   re-signs that immutable release. The current build source is `aa3b7b0`, which
   has an **additive** signed record at `release/T20-final/6c94b47` and a 5/6
   board with `soak_24h` OPEN — NOT SHIPPABLE; see
   [`CURRENT-HEAD-CLOSEOUT-AA3B7B0-20261126.md`](../../analysis/current-head/CURRENT-HEAD-CLOSEOUT-AA3B7B0-20261126.md).

Validation: `python scripts/check_summary.py` must print `SUMMARY_VALID`.
