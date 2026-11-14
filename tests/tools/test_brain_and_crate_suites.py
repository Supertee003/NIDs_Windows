"""TIER2-CRATE-001: 88 Python brain tests and 21 Rust tests existed and no gate ran them.

`brain/` is Tier-2 analytics: 21 `test_*.py` files that cover tier routing, the
detection scan, the policy decision, the enforcement *path* (that it stays
advisory), receipts and forensic evidence. `python -m pytest brain` runs them all
in under a second — and nothing in `tests/` ever did, because the suite only ever
targeted `tests/`.

Three Rust crates were in the same position: `mouth/` (the Windows security
monitor, 13 tests), `aegis_dashboard/` (8 tests) and `shield/` (`cargo check`
only, no tests). `cargo test` for two of them runs in about a second each.

These pins run the project as it is: `pytest brain` as a subprocess (so a brain
import-time side effect cannot leak into this process), `cargo check` for all
three crates and `cargo test` for the two that have tests, with case-count floors
so a silently deleted test is a failure rather than a smaller green run.

Rust pins use `--offline`: the crates are vendored in the local cargo cache, and a
gate must not depend on the network. A missing cache is reported as a skip.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CARGO = shutil.which("cargo")

BRAIN_MINIMUM_CASES = 88
CRATE_TEST_FLOORS = {"mouth": 13, "aegis_dashboard": 8}


def _run(args: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=cwd, timeout=900,
    )


def test_the_brain_suite_passes() -> None:
    proc = _run([
        sys.executable, "-m", "pytest", "-q", "brain", "-p", "no:cacheprovider",
    ])
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output[-3000:]
    passed = re.search(r"(\d+) passed", output)
    assert passed, output[-2000:]
    assert int(passed.group(1)) >= BRAIN_MINIMUM_CASES, (
        f"the brain suite dropped to {passed.group(1)} cases from {BRAIN_MINIMUM_CASES}"
    )
    assert " failed" not in output


needs_cargo = pytest.mark.skipif(CARGO is None, reason="cargo not installed")


@pytest.mark.parametrize("crate", ["mouth", "shield", "aegis_dashboard"])
@needs_cargo
def test_crate_checks_offline(crate: str) -> None:
    proc = _run([CARGO, "check", "--offline", "--manifest-path", f"{crate}/Cargo.toml"])
    output = proc.stdout + proc.stderr
    if "no matching package" in output or "failed to load source" in output:
        pytest.skip(f"{crate} dependencies are not in the local cargo cache")
    assert proc.returncode == 0, output[-3000:]


@pytest.mark.parametrize("crate", sorted(CRATE_TEST_FLOORS))
@needs_cargo
def test_crate_tests_pass_and_do_not_shrink(crate: str) -> None:
    proc = _run([CARGO, "test", "--offline", "--manifest-path", f"{crate}/Cargo.toml"])
    output = proc.stdout + proc.stderr
    if "no matching package" in output or "failed to load source" in output:
        pytest.skip(f"{crate} dependencies are not in the local cargo cache")
    assert proc.returncode == 0, output[-3000:]
    counts = [int(n) for n in re.findall(r"test result: ok\. (\d+) passed", output)]
    failures = [int(n) for n in re.findall(r"test result: FAILED\. (\d+) passed; (\d+) failed", output)]
    assert counts, output[-2000:]
    total = sum(counts)
    assert not re.search(r"test result: FAILED", output), output[-2000:]
    assert not failures
    assert total >= CRATE_TEST_FLOORS[crate], (
        f"{crate} dropped to {total} passing tests from {CRATE_TEST_FLOORS[crate]}"
    )
