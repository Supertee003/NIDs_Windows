"""FOREIGN-TOOLCHAIN-001: the TypeScript and second-Go modules had no gate either.

Two modules sit outside `zig build` and outside `nose/`:

* `ts_policy/` — the advisory TypeScript policy plane: 6 `src/*.ts` files and 8
  `tests/*.test.ts` files, a `tsc --noEmit` typecheck and 76 `node --test` cases.
  Advisory only: it seals and exports policy IR, and must never enforce.
* `go/aggregator/` — the alert correlator: a second Go module with its own
  `go.mod`, 8 `.go` files.

Both were exercised only by whoever remembered to run them. These pins run the
project's own scripts (`npm run typecheck`, `npm test`) rather than a command
invented here, so a change to the project's own definition of "the tests" is
picked up instead of diverging.

The pins skip when a toolchain is missing (no origin `node_modules`, no `go`
binary) and report it, rather than passing quietly.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TS = ROOT / "ts_policy"
AGG = ROOT / "go" / "aggregator"

NPM = shutil.which("npm") or shutil.which("npm.cmd")
GO = shutil.which("go")

# The suite had 76 passing cases when this pin was written. Growing is fine;
# losing cases is the regression this catches.
TS_MINIMUM_CASES = 76


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    # `node --test` prints `ℹ pass 76`; decoding must not depend on the host code page.
    env = {**os.environ, "NO_COLOR": "1", "FORCE_COLOR": "0"}
    return subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=cwd, timeout=900, env=env,
    )


ts_ready = pytest.mark.skipif(
    NPM is None or not (TS / "node_modules").is_dir(),
    reason="npm or ts_policy/node_modules not present",
)
go_ready = pytest.mark.skipif(GO is None, reason="Go toolchain not installed")


@ts_ready
def test_typescript_typechecks_strict() -> None:
    proc = _run([NPM, "run", "typecheck"], TS)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@ts_ready
def test_typescript_suite_passes_and_does_not_shrink() -> None:
    proc = _run([NPM, "test"], TS)
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    # `node --test` prints `ℹ pass 76` / `ℹ fail 0`, sometimes behind a glyph or
    # ANSI escape that the host code page may mangle; the last bare occurrence wins.
    passes = re.findall(r"\bpass\s+(\d+)\b", output)
    fails = re.findall(r"\bfail\s+(\d+)\b", output)
    assert passes and fails, f"could not read the node --test summary:\n{output[-2000:]}"
    assert int(fails[-1]) == 0, output[-2000:]
    assert int(passes[-1]) >= TS_MINIMUM_CASES, (
        f"the TypeScript suite dropped to {passes[-1]} cases from {TS_MINIMUM_CASES}"
    )


@go_ready
def test_aggregator_vets() -> None:
    proc = _run([GO, "vet", "./..."], AGG)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not proc.stderr.strip(), proc.stderr


@go_ready
def test_aggregator_builds(tmp_path: Path) -> None:
    target = tmp_path / ("aggregator.exe" if shutil.os.name == "nt" else "aggregator")
    proc = _run([GO, "build", "-o", str(target), "."], AGG)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert target.exists() and target.stat().st_size > 0


@go_ready
def test_aggregator_test_files_compile() -> None:
    proc = _run([GO, "test", "-run", "XXXNO_SUCH_TEST", "-count=1", "./..."], AGG)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "no tests to run" in (proc.stdout + proc.stderr)
