# CI quality gates — actual configuration and local tools

> Scope: build source `4dd3393`. AEGIS-PLAN-018.
> This page corrects an earlier statement that no CI workflow existed. The
> workflow files are present and are listed below.

## 1. Workflows

| File | Role |
|---|---|
| `.github/workflows/ci.yml` | Canonical multi-language CI: `zig-build-test`, `rust-pep-build`, `c-native-build`, `shield-build`, Python tests, Go Nose, Go aggregator (support), TypeScript policy, and a `ci-matrix` gate job |
| `.github/workflows/host-regression.yml` | Host regression entrypoint; requires an appropriately configured runner and is not proof that a host run happened |

`ci.yml` triggers on push to `main`, `develop`, `release/*`, `codex/**`, `fix/**`,
on pull requests to `main`, `develop`, `codex/**`, and on manual dispatch.

## 2. Gate semantics

`ci_coverage.json` is the machine-readable contract:

- canonical required project missing → FAIL;
- canonical required project non-success → FAIL;
- support project → reported, non-fatal.

Go aggregator is `SUPPORT`; it is reported but does not gate canonical health.
The gate job id is `ci-matrix`.

## 3. Local quality tools (not CI runners)

| Tool | What it proves |
|---|---|
| `tools/truth.py verify` | Machine maps carry build source `4dd3393`, ancestor of HEAD, source paths clean |
| `scripts/doc_checker.py` | Required docs exist, `aegisctl` code-fence commands exist, env docs map to code, component JSON parses |
| `scripts/check_summary.py` | Evidence level summary consistency (`SUMMARY_VALID`) |
| `tools/release_engineering.py --verify` | 690 artifact digests match recorded values |
| `tools/final_audit.py --check` | Current gate board consistency |
| `pytest tests/docs tests/release` | Documentation and release gates |

A local tool passing is not a GitHub Actions result. This page records both
surfaces without merging them.

## 4. Status

| Claim | Status |
|---|---|
| Workflow files exist and declare canonical jobs | E1 PASS (files read directly) |
| `ci_coverage.json` carries canonical/support semantics | E1 PASS |
| Local gate tests pass at current HEAD | E2 PASS (`262 passed` for `tests/docs tests/release`) |
| A green GitHub Actions run for build source `4dd3393` | **NOT RECORDED IN THIS TREE** |

## 5. Open work

Record an actual Actions run URL, commit, and job list in an evidence entry if
a green CI result is required as proof. Do not infer it from workflow presence.

---

See also: [`../ci_coverage.json`](../ci_coverage.json),
[`../../.github/workflows/ci.yml`](../../.github/workflows/ci.yml),
[`../runtime/TOOLCHAIN_INVENTORY.md`](TOOLCHAIN_INVENTORY.md).
