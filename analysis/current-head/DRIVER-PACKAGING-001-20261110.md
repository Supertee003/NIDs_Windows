# DRIVER-PACKAGING-001 — one driver image, one source path (S2-05)

**Created:** 2026-11-10
**Build source commit:** `e68cd96` (this record changes packaging inputs only; the
Zig/Go/Rust/C runtime is untouched)
**Finding:** `SYSTEM-SURVEY-001` §S2-05
**Evidence level:** E2 (static + unit proof). No host window ran for this patch.

---

## 1. What was wrong

The tree contained three things that could install a kernel driver, and they did
not agree on which `aegis_wfp.sys` that was:

| Entry point | Driver source before this patch | State of that source |
|---|---|---|
| `installer/aegis.nsi:72` | `drivers\wfp_callout\aegis_wfp.sys` | 28,136 B, Oct 16, **no build target refreshes it** |
| `tools/installer.py:35,256` | `build\x64\wfp\aegis_wfp.sys` | 42,896 B, current WDK output |
| `scripts/package_release.ps1:51` | `build\x64\wfp\aegis_wfp.sys` | current WDK output |
| `tools/release_candidate.py:46` | `drivers/wfp_callout/aegis_wfp.sys` **and** `.../aegis_minifilter.sys` | neither file is a build output; the minifilter copy does not exist in that directory at all |

So the answer to "which driver does this product deploy" depended on which file
the operator ran — and the release-candidate path could package a WFP image that
predates EVT-231 with no error, because its copy is guarded by
`if p.exists()`. Nothing in the tree recorded which image an E5 run had used.

## 2. What changed

| File | Change |
|---|---|
| `installer/aegis.nsi` | the `File` directive now takes `build\x64\wfp\aegis_wfp.sys`, the same literal as `tools/installer.py` and `scripts/package_release.ps1`, with the reason recorded in place |
| `tools/release_candidate.py` | `DRIVERS` now names the two WDK build outputs (`build/x64/wfp`, `build/x64/minifilter`) instead of the source tree |
| `tests/release/test_driver_packaging_sources.py` | new: pins the invariant across all four entry points (5 tests) |

The test is written against the *invariant*, not the current file list, so a new
packaging entry point that reintroduces the old path fails:

1. no entry point names `drivers/wfp_callout/*.sys` outside a comment;
2. the three driver-shipping entry points name `build\x64\wfp\aegis_wfp.sys`;
3. every NSIS `File` directive that packages a `.sys` takes it from
   `build\x64\...` (mutation control: reverting the `aegis.nsi` directive fails
   3 of the 5 tests — recorded below);
4. `tools/release_candidate.py`'s `DRIVERS` list is exactly the two build
   outputs (read from the AST, not from a regex);
5. no `scripts/*.ps1|*.bat|*.py` still writes a `.sys` into `drivers/wfp_callout/`.

Only tracked files are read: the scratch copy under `.work/clean-run/` is
another tree and must not decide this verdict.

## 3. Verification

```
python -m pytest -q tests/release/test_driver_packaging_sources.py   -> 5 passed
mutation: revert aegis.nsi driver directive                          -> 3 failed, 2 passed
python -m pytest -q tests/release tests/security tests/tools         -> 480 passed, 5 failed
```

The 5 failures in the wider run were not regressions in behaviour:

- `tests/release/test_fresh_deploy.py` (3) and
  `test_t17_perf_ci_installer.py::test_ac3_verify_mode_detects_drift` fail while
  the two edited artifacts are **uncommitted**, which is the digest gate from
  GATE-HONESTY-001 doing its job (`FAIL - artifacts drifted from recorded commit
  digests: installer/aegis.nsi, tools/release_candidate.py`). All four pass after
  the commit plus `release_engineering.py --refresh-digests`; re-run recorded in
  §5.
- `tests/security/test_scope_ratchet.py::test_product_evidence_debt_has_not_grown`
  failed **before this patch** on a clean `HEAD`: the S3-01 evidence entry names
  `tools/aegisctl/config.py`, which closed one debt item, so the baseline had to
  be trimmed with `python tools/evidence_debt.py --write`. That trim is part of
  this commit and is a consequence of the previous patch, not of this one.

## 4. Limitations (stated, not hidden)

1. **`installer/aegis.nsi` is still a second installer.** This patch makes the
   two installers ship the same *image*; it does not make them equivalent. The
   NSIS path still performs no driver hash verification, no `configs` ACL
   hardening and no uninstall proof of WFP-lightweight-filter cleanup, all of
   which `tools/installer.py` now does. Retiring it needs the TRASH-002 test
   (no reference, no manifest entry, record) and an owner decision about which
   installer is the product; that decision was not made here.
2. **No E5.** Nothing in this patch proves which image a host is running. The
   installed `AegisWfp` is still `F63195B0…`/`06CC8E23…` per the last host
   window; only a host window that stops the service, replaces the image and
   re-hashes the installed file can close S1-01.
3. **The stale binary is still on disk.** `drivers/wfp_callout/aegis_wfp.sys`
   (28,136 B) is untracked build output, so git cannot delete it. It is now
   referenced by no packaging path and by no build script; removing it is a host
   cleanup, not a repository change.
4. **`installer.nsi` (repository root)** packages driver *sources* and was not
   changed: it ships no `.sys` at all, so it is out of this finding's scope. It
   remains a third, non-shipping installer description.

## 5. Re-run after commit and digest refresh

```
python tools/release_engineering.py --refresh-digests
python -m pytest -q tests/release/test_driver_packaging_sources.py
python -m pytest -q tests/release/test_fresh_deploy.py tests/release/test_t17_perf_ci_installer.py
python -m pytest -q tests/release tests/security tests/tools
python tools/truth.py verify
```

Results are recorded in the evidence entry for this patch rather than predicted
here.
