# Master Audit — Phase 7 (Verification & Release truth)

**Target HEAD:** `0867b5f045b7886648e3841f6dfeb8eaad1e2672`
**Build source (unchanged by this records-only slice):** `661fb768dc1c8eeb0f79e4e437807f2eac08c9ff`
**Date:** 2026-11-24
**Patch ID:** `P7-VERIFICATION-TRUTH-20261124`
**Tracker:** https://github.com/Supertee003/NIDs_Windows/issues/46
**Classification convention:** "ตรวจพบ" = confirmed from current file/source; "ต้องตรวจ Source" = suspicion requiring source proof; "แนะนำเพิ่ม" = recommendation, not a proven defect.
**Evidence level:** E1/E2 static pins only. No new E4/E5, soak, Windows host, signing, install or release verification is claimed.

---

## STOP-THE-LINE disposition

**V&R-01 was a latent build/runtime-mismatch trigger** (`AGENTS.md` STOP-THE-LINE list). `tools/final_audit.py` kept a second build-source boundary (`RUNTIME_PATHS`) that differed from the canonical `tools/truth.py:SOURCE_PATHS`. Both lists currently resolve to `661fb76`, so today's release verdict was not false; the risk was that a future source-only change to `configs/`, `Cargo.lock`, `requirements.txt` or WDK scripts would move build source without invalidating soak/signature freshness. A tracker was filed **before** the patch (issue #46), the duplicated tuple was removed, and equality is now pinned. This is disclosure plus correction, not a silent workaround.

No release tag, signature, key, gate count, rule, wire layout, authority behavior or source commit changed. `v1.1` remains immutable at signed candidate `466a226` / build source `a53eda8`; current build source remains `661fb76`.

---

## 1. V&R-01 — duplicated release-freshness source boundary · ตรวจพบ · FIXED

- **Paths / current text (before patch):** `tools/final_audit.py:337-340` — `RUNTIME_PATHS = ("src", "nose", "brain", "ts_policy", "shared", "contracts", "drivers", "go", "build.zig", "CMakeLists.txt", "Cargo.toml", "rust-src")`; `:691-705` `_runtime_source()` used it for `git log -1 ... -- *RUNTIME_PATHS`. Canonical `tools/truth.py:44-66` `SOURCE_PATHS` instead includes `shield`, `bridge`, `mouth`, `configs`, `Cargo.lock`, `requirements.txt`, `scripts/wdk_build_production.ps1`, `scripts/wdk_build_minifilter.ps1`, and omits `ts_policy`/`contracts`.
- **Reason:** two definitions of the same ADR-0008 boundary can diverge. Both currently resolve to `661fb76` (read-only `git log` check), so this was latent, not a present false PASS.
- **Replacement:** `final_audit.py` now imports `SOURCE_PATHS` from `truth.py` as `RUNTIME_PATHS` after adding the tools directory to `sys.path` (needed because tests load the module by file path). A comment records V&R-01.
- **Acceptance:** `tests/release/test_vr_truth.py::test_release_freshness_uses_the_canonical_truth_boundary` asserts tuple equality and that `configs`/WDK scripts are present and `ts_policy` absent. Six release gates remain six.

## 2. V&R-02 — `build_manifest.json` component commits self-refuted · ตรวจพบ · FIXED

- **Path / current text (before patch):** `build_manifest.json:5` `"source_commit": "661fb76"`, while `:30,41,52,63,74,85,96,107,118,129,139,149` carried `419e9f5`, `ee1010e`, `daf9088`, `97bb4a1`, `bca337e`, `a38f414`, `0b36002`, `557b4ce`, `4dc9c09`, `de574b6`. `tools/release_engineering.py:278-309` generates every component with one `commit`, and `:540` re-stamped only `source_commit`. Read-only `git show` found most recorded component hashes unresolvable in current history.
- **Reason:** no code path produced twelve independent component commits; digest verification ignored them, so stale/nonexistent provenance passed silently.
- **Replacement:** `refresh_digests()` now re-stamps every `components[].commit` with the same `commit` used for `source_commit`; the committed manifest's twelve component commits were re-stamped to `661fb76`. No artifact path, digest or size changed.
- **Acceptance:** `tests/release/test_vr_truth.py` asserts all committed component commits equal the header, and a tmp-path test proves `refresh_digests("new456")` updates both fields.

## 3. V&R-03 — soak gate checked declared hours, not observed hours · ตรวจพบ · FIXED

- **Path / current text (before patch):** `tools/final_audit.py:510-534` filtered candidates by `required_hours >= SOAK_HOURS` and then PASS/problems/stale; `elapsed_hours` was only printed in `label`. `analysis/current-head/POST-SOAK-CLOSEOUT-466A226.md:49-50` told operators `final_audit.py:335` hard-codes `24.0`.
- **Reason:** `{"verdict":"PASS","required_hours":24,"elapsed_hours":0.1,"problems":[]}` closed `soak_24h`. The operator artifact (`admin-evidence/e5-clean-host-20261120-final/soak-24h-delta-final.json:2-6`) is genuinely `36.52/24.0`, so today's verdict was not false; the evaluator was weaker than the documented rule.
- **Replacement:** `evaluate_soak()` now requires numeric non-bool `elapsed_hours >= required_hours` after the existing 24 h declaration filter, returning a detail containing `observed elapsed_hours` when the claim is short or missing. Timestamp ordering was not added because current test/artifact shapes do not all carry `soak_start`; it is recorded as a hardening option in issue #46.
- **Acceptance:** new pins reject `0.1/24.0` and missing elapsed, accept `24.4/24.0`; all existing release-board soak tests still pass.

## 4. V&R-04 — stale `--refresh-digests` docstring · ตรวจพบ · FIXED

- **Path / current text (before patch):** `tools/release_engineering.py:469-473` — `whose directory rules drifted away ... still lists the non-existent core/ and config/ trees, omits src/ and configs/, and picks up gitignored Cython build output. Regenerating today therefore DESTROYS provenance ...`
- **Reason:** current `collect_artifacts()`/`_is_excluded()` includes `src`/`configs`, has no `core`, and excludes Cython build byproducts. The paragraph described a rule that no longer exists in the same file.
- **Replacement:** docstring now labels that collector drift HISTORICAL (V&R-04), states the current full-regeneration rule, and keeps the bounded `--refresh-digests` contract.
- **Acceptance:** pin asserts the HISTORICAL label is present and the stale sentence is gone.

## 5. V&R-05 — `security-scan` required CANONICAL but advisory in CI · ตรวจพบ · FIXED

- **Path / current text (before patch):** `ci_coverage.json:121-127` — `"required": true`, `"classification": "CANONICAL"`; `.github/workflows/ci.yml:252-263` comment — `Non-blocking by decision (exit-code 0) ... findings stay advisory` with `exit-code: 0`.
- **Reason:** Trivy cannot return non-success with `exit-code: 0`, so the matrix advertised a blocking gate the workflow deliberately did not implement.
- **Replacement:** `ci_coverage.json` now marks `security-scan` `required: false`, `classification: SUPPORT`, with a note citing CI-GATE-107, the pinned action, `exit-code 0`, and the absent triage SLA. The job still runs and is reported.
- **Acceptance:** pin asserts SUPPORT/non-required and the note tokens; `python tools/ci_coverage.py --json` reports no `failed_required`.

## 6. V&R-06 — `ts-policy` required CANONICAL but advisory-only · ตรวจพบ · FIXED

- **Path / current text (before patch):** `ci_coverage.json:59-63` — `"required": true`, `"classification": "CANONICAL"`; `AGENTS.md:96,118` says TypeScript is advisory-only with no production output and no enforcement/runtime ownership. `tools/ci_coverage.py:21-24` makes any required non-success job a FAIL.
- **Reason:** an authoring check with no runtime artifact could block a runtime release, contradicting the authority map. The same contradiction existed in `tools/release_engineering.py:306-307` and `build_manifest.json` (`ts-policy` `required: true`).
- **Replacement:** CI coverage, the manifest generator and the committed manifest now mark `ts-policy` `required: false`, `classification: SUPPORT`, note `Advisory policy authoring only; no runtime artifact or enforcement authority.` The `ts-policy-build` job still runs and is reported; no workflow `needs` entry was removed.
- **Acceptance:** pins assert SUPPORT/non-required in both JSON files and that the note says no runtime artifact. Cross-language matrix still includes `typescript`; `ci_coverage.py` remains green.

## 7. V&R-07 — current-facing docs pinned superseded `ab0fa17` · ตรวจพบ · FIXED

- **Paths / current text (before patch):** `SECURITY.md:8` — `current build source ab0fa17 (audit-close slice)`; `docs/STRUCTURE.md:5-6,100,108` — `CURRENT ... ab0fa17`, records HEAD `6540fce`, and two more `ab0fa17` labels; `docs/SECURITY_THREAT_MODEL.md:4` — `at build source ab0fa17`; `docs/architecture/SECURITY_BOUNDARIES.md:3` — `Verified against current source at build source ab0fa17`.
- **Reason:** `AGENTS.md:5`, `AUTHORITY_MAP.json:2`, `build_manifest.json:5` and P4 audits establish `661fb76`; none of these four files carried a HISTORICAL banner.
- **Replacement:** all four now say `661fb76`. `docs/STRUCTURE.md` no longer freezes a records HEAD value; it points to `git rev-parse HEAD` because this slice is records-only.
- **Acceptance:** pin asserts no `ab0fa17` and presence of `661fb76` in all four files.

## 8. V&R-08 — waiver exit path prints FAIL but returns 0 · แนะนำเพิ่ม · OPEN

- **Paths / current text:** `tools/final_audit.py:983-989` — `if args.accept_waivers and verdict["shippable_with_waiver"]: ... print("FAIL: not a full shippable release ... (unproven)", file=sys.stderr); return 0`; `docs/gates/waivers.json:3` currently describes that success path; `:4` `"waivers": []`.
- **Reason:** an owner waiver mode can print a FAIL banner while automation observes exit 0. It is latent because no waiver is active, and the existing waiver rule explicitly expects this return path, so it is a contract decision rather than a proven breach of that rule.
- **Replacement direction:** use a distinct non-zero machine-readable status such as `WAIVED_NOT_SHIPPABLE`, or document exit 0 as an explicit owner-only waiver mode and keep it out of release automation. Do not silently change it in a truth-labelling patch.
- **Acceptance:** issue #46 remains open with exact file:line, direction and the requirement that any change preserve the six-gate contract and be pinned by `tests/release/test_release_waivers.py`.

---

## Additional decision recorded

- `soak_start`/`checked_at` ordering was recommended in the audit but not added: current small test artifacts omit `soak_start`, and forcing it would be a broader artifact-schema change unrelated to the V&R-03 false-PASS class. It is listed in issue #46 as optional hardening, not claimed fixed.

## Flow / contract impact

```text
OLD  final_audit.RUNTIME_PATHS     -> local tuple (can diverge from ADR-0008)
NEW  final_audit.RUNTIME_PATHS     -> truth.SOURCE_PATHS (single boundary)
OLD  soak_24h                      -> required_hours only
NEW  soak_24h                      -> required_hours + observed elapsed_hours
OLD  build_manifest components     -> stale/unresolvable commits beside 661fb76
NEW  build_manifest components     -> all stamped 661fb76; refresh keeps them aligned
OLD  security-scan / ts-policy     -> required CANONICAL
NEW  security-scan / ts-policy     -> SUPPORT, jobs still run and report
OLD  four security/structure docs  -> ab0fa17 as current
NEW  four security/structure docs  -> 661fb76
```

- **Wire/ABI bytes/rules/authority behavior/host effects:** none changed.
- **Release identity:** unchanged (`v1.1`, `466a226`, `a53eda8`, 6/6 gates). No new tag, signature, key, E4/E5 or soak claim.
- **Build source:** unchanged (`661fb76`); all edited paths are records-only per `tools/truth.py:40-66`.
- **Evidence level:** E1/E2 static pins only.

## Completion gate

**PASS (E1/E2, records-only)** requires: new V&R pins pass; existing release/board/CI pins pass after digest rebaseline; `TRUTH_VALID @ 661fb76`; 674/674 digests; BAD LINKS none; `SUMMARY_VALID`; CI-equivalent pytest green. V&R-08 and optional soak timestamp ordering remain explicitly open in issue #46. Deferred source findings in issues #44/#45 and MASTER-AUDIT-P4/P5/P6 are not claimed fixed by this records-only slice.
