# Detection coverage — status vocabulary and canonical pointers

> This page defines words. It does **not** duplicate the 23-row matrix or invent
> a status. The canonical rule inventory is
> [`docs/portfolio/DETECTION_CATALOG.md`](../portfolio/DETECTION_CATALOG.md);
> the current-source row-by-row projection is
> [`docs/portfolio/DETECTION_MATRIX_CURRENT.md`](../portfolio/DETECTION_MATRIX_CURRENT.md).
> Scope: [`docs/SCOPE.md`](../SCOPE.md) — detection-only / observe-only.

## 1. Status vocabulary — do not collapse these into "Supported"

| Status | Meaning |
|---|---|
| `CATALOGUED` | Rule ID, name, category and catalog pattern are present in `configs/Rules.json` |
| `IMPLEMENTED` | A production code path can evaluate the rule's catalog pattern |
| `UNIT_TESTED` | A fixture/vector pins the rule at E1/E2 level |
| `INTEGRATION_TESTED` | The rule participates in a recorded cross-component test at its own commit |
| `LIVE_TESTED` | A real host sensor produced a recorded positive/negative result |
| `QUALIFIED` | Full qualification at the current build source under the release gate rules |

A rule may hold several statuses at once. `CATALOGUED` never implies `LIVE_TESTED`;
a fixture is not a live detector firing. `QUALIFIED` is not granted by this page.

## 2. Current recorded census (unchanged)

| Measure | Recorded value | Boundary |
|---|---|---|
| Catalog | 23/23 | `configs/Rules.json` with fixture vector and shared rule-ID hash |
| Code-path evaluable | 23/23 | Zig evaluates `match_pattern`; Python `regex_pattern` is advisory Tier-2 |
| Host-evaluable | 22/23 | Recorded census where R2003 was blocked by FN-1; at `aa3b7b0` R2003 has one narrow E5 re-measurement, but the matrix as a whole is not re-measured |
| Live positive proof | L4 family, strongest on R9006 | one lab host/interface; loopback is a self-test binding |
| Full matrix E5 | not re-measured at `aa3b7b0` | historical rows stay historical |

The pinned strings `| Host-evaluable | 22/23 |`, `**22/23** — R2003 blocked by FN-1`
and `host-evaluable coverage (R2003/FN-1)` are deliberately not rewritten.

## 3. Required columns in the canonical matrix

The row-by-row page already carries: Rule ID, Name, Category, Data Source,
Required Fields, Unit Test, Integration Test, Live Host Proof and Known
Limitations. Add a row only with its evidence location and commit; never fill a
cell with `PASS` unless an artifact exists at that commit.

## 4. R2003 special note

R2003 (PowerShell cradle) was historically blocked by FN-1 because ProcessStart
v0–v4 carried no `CommandLine`. Since `493648f` a read-only producer recovers it,
and at `aa3b7b0` there is a narrow E5 result with one positive and two negative
controls. The remaining gap is the **un-re-measured full matrix**, not the
existence of the field. See
`analysis/current-head/R2003-CMDLINE-HOST-PROOF-E5-AA3B7B0-20261126.md`.
