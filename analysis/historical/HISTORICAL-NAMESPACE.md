# Logical historical namespace — release / E6 / E7 records

**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5` (unchanged)  
**SCOPE:** provenance labelling only. No evidence level, result, gate verdict or release identity changes.

This page is the labelled namespace for pre-`aa3b7b0` release, E6 and E7 records
that still live under `analysis/current-head/`. They are **not moved on disk**:
frozen signed trees under `release/T20-final/` and several current-facing docs
reference those exact paths, and rewriting them would modify signed bytes or
force unreviewed pointer churn. The namespace is therefore declared in
`EVIDENCE_INDEX.json` (`historical: true`, `build_source`,
`evidence_namespace: "historical"`) and indexed here. Nothing is deleted.

| Evidence ID | Level | Build source of the record | Record path | Current-source claim? |
|---|---|---|---|---|
| `SIGN-RELEASE-001-E7-20261114` | E7 | `1fa877c8fca3050eacfcdda000e9831f2743cade` | `analysis/current-head/SIGN-RELEASE-001-20261114.md` | No — HISTORICAL |
| `E6-BURST-001-E6-20261114` | E6 | `1fa877c8fca3050eacfcdda000e9831f2743cade` | `analysis/current-head/E6-BURST-001-20261114.md` | No — HISTORICAL |
| `RC-REBUILD-001-E7-20261114` | E7 | `7c604d5b0022157020e20e78045cc2c97a337ddd` | `analysis/current-head/POST-SOAK-PATCHES-20261114.md` | No — HISTORICAL |
| `RC-REBUILD-002-E7-20261118` | E7 | `4169839bff11937060ed4471b3a74717f11a50c3` | `analysis/current-head/RC-BECE8F1-20261118.md` | No — HISTORICAL |
| `SIGNED-RC-A53EDA8-E7-20261120` | E7 | `a53eda8344a20f86ad4f4e4001e9b3d648067671` | `analysis/current-head/SIGNED-RC-A53EDA8-20261120.md` | No — HISTORICAL |
| `V1.1-PUBLISHED-ASSET-VERIFICATION-E7-20261122` | E7 | `a53eda8344a20f86ad4f4e4001e9b3d648067671` | `analysis/current-head/V1.1-RELEASE-CLOSEOUT-20261122.md` | No — HISTORICAL |

The build sources above are derived with the same rule as `tools/truth.py`:
`git log -1 --format=%H <records-head> -- <SOURCE_PATHS>`. They are the last
commits touching the source/build tree at each record's head, not the
`build_manifest.json` stamp carried at that time (which could itself be stale).

`LOOPBACK-BPF-E6-AA3B7B0-20261126` is deliberately **not** in this namespace:
its `build_source` is `aa3b7b0` and it is marked `historical: false`. It is
narrow E6 for two `host_live` tests only, not a full current-source E6/E7.

Published release identity remains `v1.1` / `466a226` / `a53eda8` and the Ed25519
anchor is unchanged. This page grants no new release or E7 credit.
