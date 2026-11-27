# Source-slice decision card — remaining non-soak work

**ORIGINAL DECISION RECORD (HISTORICAL):** written at build source
`aa3b7b0161e425e54155d5767737bffcde7939b5`, records tip
`61be9bc51ba95ce8499a67a6eb7bf373e887062d`. Soak is deliberately last and is
not touched here.

**UPDATE (2026-11-28):** the owner selected **option B — execute on main with
full rebaseline**. AEGIS-004a moved the build source to `3e7e591`; AEGIS-008
then moved it to `3c78c96ebf397b4e1fa052963acc4bdd6a6945d8`; AEGIS-004b then
moved it to `473b3fe4820568f9384b6768c25af59578e84f08`. AEGIS-004a and
AEGIS-008 are E2-only transactions; AEGIS-004b is E2 plus a narrow private-pipe
E3 counter proof. All three have machine maps rebaselined and digests refreshed.
The board is 4/6 with `release_signature` and `soak_24h` OPEN; NOT SHIPPABLE.
No gate threshold, waiver, verdict or soak rule changed. This page remains a
decision record, not evidence; the applied patch records are
[`AEGIS-004A`](../analysis/current-head/AEGIS-004A-CODEC-STRICT-E2-20261128.md),
[`AEGIS-008`](../analysis/current-head/AEGIS-008-SENSOR-E2-20261128.md) and
[`AEGIS-004B`](../analysis/current-head/AEGIS-004B-V1-GATES-E2E3-20261128.md).

## 1. Why these slices were prepared but not applied

Every target file below is under a `SOURCE_PATHS` entry in `tools/truth.py:44-66`
(`src`, `nose`, `shared`, `brain`, `drivers`, …). Under ADR-0008 a commit touching
those paths **moves the build source** off `aa3b7b0`. That has three concrete
consequences:

1. All machine maps must be rebuilt with the new source commit and re-verified.
2. The signed tree `6c94b47` no longer contains the runtime, so
   `tools/final_audit.py --check` turns `release_signature` **OPEN** — the board
   would go from 5/6 to 4/6 until a new owner-authorized signature record exists.
3. Any E5/E6 result tied to `aa3b7b0` becomes historical for the new source.

None of those is a documentation cleanup. They are why Card B of
[`docs/OWNER-ACTIONS.md`](OWNER-ACTIONS.md) requires an explicit decision. This
page makes the pending transactions reviewable without silently regressing the
board.

## 2. Ready transactions (original state; code not applied at write time)

After the option-B update above: `AEGIS-004-CODEC-STRICT-01` was applied as
AEGIS-004a; its remaining v1 field gates and CLI reject-counter pin were then
applied as AEGIS-004b at `473b3fe` (the Go short-write seam had already been
closed by AEGIS-008 at `3c78c96`); `AEGIS-008-SENSOR-E2-01` was applied at
`3c78c96`; the `AEGIS-003`/`AEGIS-009` row remains pending. Rows below retain
their original pre-decision wording for auditability.

| Patch ID | Audit | Change class | ABI / wire | Evidence after execution |
|---|---|---|---|---|
| `AEGIS-004-CODEC-STRICT-01` | [`CODEC-VALIDATION-E1-AUDIT`](../analysis/current-head/CODEC-VALIDATION-E1-AUDIT-AA3B7B0-20261128.md) | validation-only: exact legacy length, complete provenance tuple, v1 field gates, short-write/reject tests | none | E2; no host claim |
| `AEGIS-008-SENSOR-E2-01` | [`SENSOR-COVERAGE-E1-AUDIT`](../analysis/current-head/SENSOR-COVERAGE-E1-AUDIT-AA3B7B0-20261128.md) | hermetic VLAN/QinQ, IPv6 ext-chain, truncation matrix, pipe sink seam | none | E2; `SENSOR_COVERAGE` host rows stay `NOT_PROVEN` |
| `AEGIS-003` / `AEGIS-009` | health / kernel lifecycle audit | see the health-and-lifecycle E1 audit when recorded | to be declared per transaction | E2 only unless an owner-run host window exists |

Each transaction must still be declared with PATCH-ID, FLOW-ID, TARGET HEAD,
TARGET FILES, TARGET SYMBOLS, IN/OUT OF SCOPE, CONTRACT/ABI/AUTHORITY/STATE/TEST/
EVIDENCE impact per `AGENTS.md`, then built, tested, rebaselined and given its own
evidence entry. No skip, xfail, waiver or gate threshold is part of any slice.

## 3. Options for the owner

- **A — Keep frozen (current state).** Board stays 5/6 with only `soak_24h`
  OPEN; source-level gaps stay honestly marked PARTIAL / NOT_PROVEN.
- **B — Execute on main with full rebaseline.** Requires accepting the temporary
  `release_signature` OPEN and an owner-authorized new signature record over the
  new source tree, plus rebuilt machine maps and fresh E2/E3 proof. This does
  **not** create a new release identity and does not close soak.
- **C — Execute in a separate worktree for evidence only.** Main keeps
  `aa3b7b0` and 5/6; the branch carries the source fix and its tests but is not
  merged until B is chosen.

No option is treated as chosen by this page. The agent will not move the build
source or create a new signature silently.

## 4. Explicitly unchanged

- Product scope: detection-only / observe-only ([`SCOPE.md`](SCOPE.md)).
- Published release identity: `v1.1` / `466a226` / `a53eda8`.
- Gate strings, verdicts, soak acceptance rule, health labels, rule census and
  pinned 22/23 strings.
- No host, driver, service, finalizer or soak action.
