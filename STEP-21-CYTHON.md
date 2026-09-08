# Step 21 — Cython (Measured Hotspots Only)

**Status:** S3 (Build verified — Cython extensions compiled; measurement/benchmark unverified)
**Files:** `brain/cython/*.pyx`, `brain/aegis_brain_cython/*.pyx`, `core/perf_benchmark.zig` (benchmark framework — unverified)
**Production Subsystem:** Cython extensions (`brain/cython/*.pyx`, `brain/aegis_brain_cython/*.pyx`)

---

## Contract (Per ROADMAP STEP 21 + docs architecture)

- Used ONLY for measured hotspots: feature extraction, numeric operations, batch processing, vectorization
- Must have BEFORE benchmark, AFTER benchmark, CPU, latency, correctness measurements
- Acceptance must include regression proof (before/after comparison)

---

## Build Verification (Verified in CI)

- `python setup.py build_ext --inplace` produces:
  - `brain/cython/aegis_hotspot.cp314-win_amd64.pyd`
  - `brain/cython/cython_regex_scan.cp314-win_amd64.pyd`
  - `brain/aegis_brain_cython/fast_scan.cp314-win_amd64.pyd`
- `.gitignore`: `.pyd` excluded; source `.pyx`/`.pxd` committed; `.c` generated files excluded
- **Not verified:** Benchmark before/after comparison (STEP 47 — performance; `core/perf_benchmark.zig` framework exists but tests unverified; measurement/benchmark evidence package missing)

---

## References

- `brain/cython/*.pyx`
- `brain/aegis_brain_cython/*.pyx`
- `core/perf_benchmark.zig` (benchmark framework — unverified)
- `core/performance_harness.zig` (performance framework — unverified)
- `docs/FILE_CLASSIFICATION.md` (Cython = measured hotspots; benchmark suite missing)
- `docs/ARCHITECTURE-TRUTH.md` (Cython framework noted as REAL build; verification unverified — STEP 47 dependency)
