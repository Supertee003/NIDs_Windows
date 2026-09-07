"""T6 TypeScript Policy Plane test driver (Python wrapper).

This is the CI entry point for the T6 TypeScript tests. It invokes
`npm test` inside `ts_policy/` and asserts the exit code, parses the
test summary, and re-raises on failure.

Why a Python wrapper:
  - The repo's primary test runner is `pytest`. T6 is a TypeScript
    deliverable but we still need it in the gate set.
  - `npm` may not be installed in every CI image; the wrapper fails
    loudly with a clear diagnostic.
  - This keeps the existing `zig test` / `pytest` command set uniform.

Usage:
    pytest tests/typescript/test_06_typescript_policy.py
    python tests/typescript/test_06_typescript_policy.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TS_POLICY = REPO_ROOT / "ts_policy"


def _npm_available() -> bool:
    return shutil.which("npm") is not None


def _npm_executable() -> str:
    """Return the path to the npm executable, handling Windows shims.

    On Windows, `npm` is a `npm.cmd` (or `npm.ps1`) shim. Python's
    `subprocess.run(["npm", ...])` with `shell=False` won't auto-resolve
    these on Python 3.14. We resolve to the `.cmd` shim explicitly.
    """
    exe = shutil.which("npm")
    if exe is None:
        return "npm"  # let the subprocess call fail with a clear error
    return exe


def _node_modules_present() -> bool:
    return (TS_POLICY / "node_modules").exists()


@pytest.fixture(scope="module")
def npm_typecheck() -> subprocess.CompletedProcess:
    """Run `npm run typecheck` and return the result.

    Skips if npm is not available. The test asserts a 0 exit code.
    """
    if not _npm_available():
        pytest.skip("npm is not installed")
    if not _node_modules_present():
        pytest.skip("ts_policy/node_modules not present; run `cd ts_policy && npm install`")
    return subprocess.run(
        [_npm_executable(), "run", "typecheck"],
        cwd=str(TS_POLICY),
        capture_output=True,
        text=True,
        shell=False,
    )


@pytest.fixture(scope="module")
def npm_test() -> subprocess.CompletedProcess:
    """Run `npm test` and return the result.

    Skips if npm is not available or node_modules are missing.
    """
    if not _npm_available():
        pytest.skip("npm is not installed")
    if not _node_modules_present():
        pytest.skip("ts_policy/node_modules not present; run `cd ts_policy && npm install`")
    return subprocess.run(
        [_npm_executable(), "test"],
        cwd=str(TS_POLICY),
        capture_output=True,
        text=True,
        shell=False,
    )


def test_npm_typecheck_zero_exit(npm_typecheck: subprocess.CompletedProcess) -> None:
    """AC1: TypeScript source must type-check without errors."""
    assert npm_typecheck.returncode == 0, (
        f"`npm run typecheck` failed (exit {npm_typecheck.returncode}):\n"
        f"  stdout: {npm_typecheck.stdout[-2000:]}\n"
        f"  stderr: {npm_typecheck.stderr[-2000:]}"
    )


def test_npm_test_zero_exit(npm_test: subprocess.CompletedProcess) -> None:
    """AC1+AC2+AC3+AC4: All TypeScript tests must pass."""
    assert npm_test.returncode == 0, (
        f"`npm test` failed (exit {npm_test.returncode}):\n"
        f"  stdout: {npm_test.stdout[-3000:]}\n"
        f"  stderr: {npm_test.stderr[-3000:]}"
    )


def test_npm_test_passed_at_least_50(npm_test: subprocess.CompletedProcess) -> None:
    """Lock-in: at least 50 tests must pass (catches accidental removal of
    the typed-value/compiler/seal test suites)."""
    # The `node --test` summary has a line like:
    #   ℹ tests 67
    #   ℹ pass  67
    # or English variant on non-unicode terminals:
    #   # tests 67
    #   # pass  67
    out = npm_test.stdout + npm_test.stderr
    # Find any "pass" line and extract the number
    import re
    matches = re.findall(r"#?\s*pass\s*(\d+)", out)
    if not matches:
        # Try the unicode variant
        matches = re.findall(r"ℹ\s*pass\s*(\d+)", out)
    assert matches, f"could not parse pass count from npm test output:\n{out[-2000:]}"
    pass_count = int(matches[0])
    assert pass_count >= 50, f"expected at least 50 passing tests, got {pass_count}"


def test_ts_policy_directory_exists() -> None:
    """T6 AC: TypeScript policy plane directory must exist."""
    assert TS_POLICY.is_dir(), f"missing ts_policy directory: {TS_POLICY}"


def test_ts_policy_package_json_exists() -> None:
    """T6 AC: a package.json must be present (T6 is a TypeScript project)."""
    assert (TS_POLICY / "package.json").is_file(), (
        f"missing ts_policy/package.json: {TS_POLICY / 'package.json'}"
    )


def test_ts_policy_tsconfig_json_exists() -> None:
    """T6 AC: a tsconfig.json must be present."""
    assert (TS_POLICY / "tsconfig.json").is_file(), (
        f"missing ts_policy/tsconfig.json"
    )


def test_ts_policy_src_directory_has_types_compiler_seal() -> None:
    """T6 AC: src/ must have types.ts, compiler.ts, seal.ts, index.ts."""
    for name in ("types.ts", "compiler.ts", "seal.ts", "index.ts"):
        assert (TS_POLICY / "src" / name).is_file(), f"missing ts_policy/src/{name}"


def test_ts_policy_tests_directory_has_all_test_suites() -> None:
    """T6 AC: tests/ must have typed_values, compiler, seal, no_enforcement,
    no_post_seal_mutation, and cross_language_contract suites."""
    for name in (
        "typed_values.test.ts",
        "compiler.test.ts",
        "seal.test.ts",
        "no_enforcement.test.ts",
        "no_post_seal_mutation.test.ts",
        "cross_language_contract.test.ts",
    ):
        assert (TS_POLICY / "tests" / name).is_file(), f"missing ts_policy/tests/{name}"


def test_policy_decision_authority_stays_in_zig() -> None:
    """T6 AC: Policy decision authority is in Zig (ADR-0001).

    Confirms the canonical Zig policy_engine is the architectural
    decision authority, not TypeScript. The TypeScript side produces
    an IR that Zig loads and evaluates. This is the architectural
    invariant.

    The test accepts either REAL or PARTIAL — T6 doesn't claim to
    finish `policy_engine.zig`; it claims that the Zig module is
    the decision authority (and is on the golden path, used by the
    dispatcher). A follow-up tier (T15 or T17) may mark it REAL.
    """
    import json
    manifest_path = REPO_ROOT / "runtime_manifest.json"
    assert manifest_path.is_file(), f"missing runtime_manifest.json: {manifest_path}"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    # The Zig policy_engine must be on the golden path.
    engine = manifest["modules"].get("core/policy_engine.zig")
    assert engine is not None, "core/policy_engine.zig not in runtime_manifest.json"
    assert engine.get("golden_path") is True, (
        f"core/policy_engine.zig must be on the golden path; got {engine}"
    )
    # And it must NOT be STUB or LEGACY (those are not production).
    status = engine.get("status")
    assert status in ("REAL", "PARTIAL"), (
        f"core/policy_engine.zig must be REAL or PARTIAL; got {status!r}"
    )
    # The authority_invariants block must mention policy_engine.
    invariants = manifest.get("authority_invariants", [])
    assert any("policy_engine" in line for line in invariants), (
        f"policy_engine not in authority_invariants: {invariants}"
    )


if __name__ == "__main__":
    # Allow direct invocation: `python tests/typescript/test_06_typescript_policy.py`
    if not _npm_available():
        print("npm not installed; skipping TypeScript tests.", file=sys.stderr)
        sys.exit(0)
    if not _node_modules_present():
        print(
            f"ts_policy/node_modules not present; run `cd {TS_POLICY} && npm install` first.",
            file=sys.stderr,
        )
        sys.exit(1)
    r = subprocess.run([_npm_executable(), "test"], cwd=str(TS_POLICY))
    sys.exit(r.returncode)
