# Host-regression encoding guard fix — 2026-11-19

**Trigger:** PR #36's `Host Regression (Phase T+K)` run `44379890825` on records
tip `a5b8de6` failed before running any test: "4 encoding violation(s) found".
The CI gate `.github/workflows/host-regression.yml` rejects any tracked file with
a UTF-16 BOM, a guard added after core/ was once committed as UTF-16LE and became
invisible to grep and Zig.

## Root cause

Four historical logs/diffs were committed as UTF-16LE in `8bcf90a` (2026-09-24):

| Path | Old bytes | New bytes |
|---|---|---|
| `.analysis/baseline-go-test.txt` | 1,778 | 868 |
| `.analysis/baseline-python-test.txt` | 4,152 | 2,027 |
| `.analysis/python-runtime-failure-detail.txt` | 10,454 | 5,145 |
| `analysis/milestone-3-critical.diff` | 434,342 | 211,770 |

They are documentation/legacy records, not in `tools/truth.py` `SOURCE_PATHS`,
not in `build_manifest.json` (674 digests unchanged), and not named by
`EVIDENCE_INDEX.json`. The conversion is records-only.

## Patch

- Decoded each file as UTF-16, rewrote as UTF-8 without BOM and with LF endings;
  stripped trailing whitespace so `git diff --check` is clean.
- Updated the four `size` fields in `inventory.json`; `reference_map.json` needs
  no change (it stores only class/role).
- No source, build config, signed candidate, installer, host state or machine-map
  source commit changed. Build source remains
  `f4cde3c503fd8b696183751a608b999768caa769`.

## Verification

- `git ls-files` BOM scan: 4 → 0.
- `git diff --check`: PASS.
- `python tools/truth.py verify`: TRUTH_VALID.
- `python tools/release_engineering.py --verify`: 674/674 digests OK.
- `python scripts/check_summary.py`: SUMMARY_VALID.

CI is re-run on the new records tip before any merge or tag. The release board
remains 5/6 with `soak_24h` OPEN; this fix does not touch the soak.
