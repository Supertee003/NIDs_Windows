# Historical / development-context documents — index

These root-level handoff files are useful development history but are **not**
source of truth for the current product:

- `AEGIS_4_PHASE_COMPLETION_STATUS_2026-09-26.md`
- `AEGIS_DEVELOPMENT_HANDOFF_2026-09-18.md`
- `AEGIS_FULL_PRODUCTION_SENSOR_HANDOFF_2026-09-27.md`
- `AEGIS_KERNEL_NIDS_DEEP_HANDOFF_2026-09-27.md`
- `AEGIS_KERNEL_NIDS_PRODUCTION_REANALYSIS_HANDOFF_2026-09-27.md`
- `AEGIS_RECOVERY_HANDOFF_RETURN_TO_NORMAL_2026-09-27.md`

Authoritative current surfaces instead:

| Subject | Current source |
|---|---|
| Product scope | [`docs/SCOPE.md`](../SCOPE.md) |
| Status / release board | [`release/release-status.json`](../../release/release-status.json) |
| Agent entry point | [`AI_CONTEXT.md`](../../AI_CONTEXT.md), [`docs/START-HERE.md`](../START-HERE.md) |
| Architecture | [`docs/architecture/DIAGRAMS.md`](../architecture/DIAGRAMS.md) |
| Verification | [`docs/portfolio/VERIFICATION_SUMMARY.md`](../portfolio/VERIFICATION_SUMMARY.md) |
| Detection matrix | [`docs/portfolio/DETECTION_MATRIX_CURRENT.md`](../portfolio/DETECTION_MATRIX_CURRENT.md) |
| Evidence | [`EVIDENCE_INDEX.json`](../../EVIDENCE_INDEX.json) |

## Why they were not physically moved

`inventory.json`, `reference_map.json`, `tests/docs/test_doc_truth_labels.py` and
the historical boundary record `analysis/current-head/FULL-BOUNDARY-001-20261109.json`
reference these files at their current root paths. A physical move would either
make machine-readable truth stale or rewrite a historical record. This index
gives them an explicit historical label without either effect. A later patch may
move them only if the maps, tests and historical pointers are updated together
and re-verified.
