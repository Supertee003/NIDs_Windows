# Step 50 — Installer Fix (Stale Embedded Snapshot — NOT Second Source-of-Truth)

**Status:** STRUCTURAL FIX APPLIED (STEP 2 + STEP 5)
**File:** `AEGIS_v5_fresh_deploy.ps1`
**Fix Date:** 2026-09-09 (Step 2 removal + Step 5 manifest integration)

---

## Problem (STEP 50 Violation — Per docs/Complete_Code_Implementation_Requirements_Report.md)

The deploy script (`AEGIS_v5_fresh_deploy.ps1`) previously embedded stale copies of:
- `.github/workflows/ci.yml` (stale CI config)
- `requirements.txt` (stale requirements)
- `Cargo.toml` (stale Rust version metadata — 1.78 instead of 1.88)
- Other source/config artifacts

This violates the STEP 50 invariant:
```
ห้าม embed stale source snapshot เป็น second source-of-truth
```

---

## Fix Applied

1. **STEP 2 (Cleanup):** File removed from git index (`git rm --cached AEGIS_v5_fresh_deploy.ps1`)
2. **STEP 5 (Manifest Integration):** `build_manifest.json` regenerated at HEAD (`61f85f6`, `b29a9c9`, `9594847`)
3. **`.gitignore`:** Added `AEGIS_v5_fresh_deploy.ps1` exclusion (line 41)
4. **Installer (`tools/installer.py`):** Confirmed to consume `build_manifest.json` (not embedded snapshot) — reads from manifest directly

---

## Current State

- `.gitignore`: `AEGIS_v5_fresh_deploy.ps1` is excluded from tracking
- File preserved locally (not deleted from disk — per user reference need for STEP 50 audit/reference)
- The deploy script must be rebuilt/re-run from current repo (not from embedded snapshot)
- `tools/installer.py` uses `build_manifest.json` as single source of truth (STEP 49 — Release Manifest verified)

---

## Exit Gate (STEP 50 — Partial; Full Verification Requires STEP 51-52 + STEP 61)

- [x] Stale embedded snapshot removed from git tracking
- [x] `.gitignore`: deployment script excluded
- [x] `tools/installer.py`: consumes `build_manifest.json` (verified structurally)
- [x] `build_manifest.json`: verified at HEAD with LF normalization (322 artifacts match; `source_commit` matches HEAD)
- [x] `runtime_manifest.json`: declares runtime_version, entrypoint, production modules, ABI versions, schema versions
- [ ] Deploy script rebuilt from current repo (requires rebuild/re-run verification — STEP 51 dependency: upgrade test requires rebuilt deploy script; STEP 52 dependency: rollback/recovery requires deploy script preservation)
- [ ] Full deploy/rebuild verification (STEP 51 — upgrade/reinstall/uninstall/rollback/recovery; requires full chain audit + current-head evidence)

---

## References

- `docs/Complete_Code_Implementation_Requirements_Report.md` (STEP 50 — "ห้าม embed stale source snapshot"; requires manifest consumption instead of embedded copies; requires upgrade/reinstall/rollback/recovery verification — STEP 51-52 dependency; requires release candidate with SBOM/checksums/signatures — STEP 64 dependency; requires final 100% proof with real event chain — STEP 65 dependency)
- `docs/ARCHITECTURE-CONVERGENCE.md` (STEP 3 — single build root = single release root; build truth invariant; install packaging must use manifest, not embedded snapshot)
- `docs/ARCHITECTURE-TRUTH.md` (STEP 6 — one release root; `build_manifest.json` verified; `runtime_manifest.json` synchronized; install packaging uses manifest; deploy script must read from manifest/repo — not embedded snapshot)
- `.gitignore` (line 41: `AEGIS_v5_fresh_deploy.ps1` excluded; updated 2026-09-09 with enhanced exclusions for legacy/backup/build artifacts + LF normalization)
- `build_manifest.json` (verified at HEAD `61f85f6` / `9594847` / `b29a9c9`; 322 artifacts; `source_commit` matches)
- `runtime_manifest.json` (STEP 5 manifest — runtime_version `5.0.0`; entrypoint `src/main.zig`; production modules `33`; subsystems `10`; ABI versions; schema versions; golden path `22` stages)
