# CI quality gates — actual configuration and local tools

> Scope: build source `4dd3393` (HISTORICAL at current source `c01e809`). AEGIS-PLAN-018.
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
| `tools/release_engineering.py --verify` | 691 artifact digests match recorded values |
| `tools/final_audit.py --check` | Current gate board consistency |
| `pytest tests/docs tests/release` | Documentation and release gates |

A local tool passing is not a GitHub Actions result. This page records both
surfaces without merging them.

## 4. Status

| Claim | Status |
|---|---|
| Workflow files exist and declare canonical jobs | E1 PASS (files read directly) |
| `ci_coverage.json` carries canonical/support semantics | E1 PASS |
| Local gate tests pass at current HEAD | E2 PASS (`276 passed` for `tests/docs tests/release`; `1518 passed, 1 skipped, 18 deselected, 27 subtests passed` for the full non-`host_live` suite) |
| Green GitHub Actions run for build source `4dd3393` | **E4 PASS — real runs recorded below** |

## 4a. Real GitHub Actions runs actually observed (2026-11-25)

Both runs were checked against the current records HEAD
`e64ea2500dec840a1c2d9af77bc2b3b3b3385d76` (build source `4dd3393`).

| Run | Trigger | Conclusion | URL |
|---|---|---|---|
| `45675880854` | `push` | `success` | https://github.com/Supertee003/NIDs_Windows/actions/runs/45675880854 |
| `45676093328` | manual `workflow_dispatch` | `success` | https://github.com/Supertee003/NIDs_Windows/actions/runs/45676093328 |

Run `45675880854`: started `2026-11-25T18:30:37Z`, last updated
`2026-11-25T18:48:26Z`. All jobs completed `success`: Rust Shield Build &
Test, Security Scan, Kernel Drivers Build (WDK) (both `.sys` outputs verified
non-empty), TypeScript Policy Build & Test, Go Aggregator (SUPPORT), Mouth
(SUPPORT), Brain Tests, C Native Build, Go Nose Build & Test, Dashboard
(SUPPORT), Rust PEP Build, Cython Accelerator Build & Test, Python Control
Plane Tests (including the build-manifest drift gate and `tools/truth.py
verify` source-commit gate), Zig Build & Test (14m32s, including `zig build
test`), Package Release, and the required `Cross-language CI Matrix`
(`success` in 6s). `Build installer`, `Verify installer output` and `Release`
are tag-only and were correctly skipped on a non-tag push.

Advisory annotations, not job failures: Node.js 20 deprecation notices, two
Go cache restore warnings (`go.sum` pattern not present), and Zig cache
save/restore service errors. None changed a job conclusion.

**Level and limits:** this is an **E4 system-integration result in hosted CI**.
It is **not** E5 (no production host, no live Npcap/driver/control-daemon
path), **not** E6, and **not** E7 (no tag, no installer payload, no signature,
no soak). The two `host_live` loopback tests are explicitly deselected by the
workflow and remain diagnosed separately in
[`testing/HOST_LIVE_DIAGNOSIS.md`](testing/HOST_LIVE_DIAGNOSIS.md).

## 5. Open work

A production-host result and release qualification still require the owner-run
runbook. CI green does not close `release_signature`, `soak_24h`, driver load,
or any current-source host proof.

---

See also: [`../ci_coverage.json`](../ci_coverage.json),
[`../../.github/workflows/ci.yml`](../../.github/workflows/ci.yml),
[`../runtime/TOOLCHAIN_INVENTORY.md`](TOOLCHAIN_INVENTORY.md).
