"""T5b AC2 + AC3: benchmark Cython vs pure-Python and lock in the speedup.

AC2 — "The hotspot is re-implemented in Cython with a measured speedup."
AC3 — "A benchmark + regression test locks the improvement; no conversion
        without a measurement."

This file is two tests:

1. `test_scan_cython_is_faster_than_pure_python` — runs the Cython-compiled
   `scan_cython` and the pure-Python `run_regex_scan` over an identical
   workload (same payload, same rules) and asserts the Cython path is at
   least `MIN_SPEEDUP` faster (default 1.10x — a conservative 10% bar that
   any non-trivial Python→Cython loop conversion must clear on this
   microbenchmark). The speedup is also printed to stdout so a developer
   can see the number when running locally.

2. `test_speedup_is_above_regression_floor` — a regression test that the
   measured speedup does not regress below `REGRESSION_FLOOR` (default
   1.05x). The 5% cushion accounts for CI noise. If this fails, the
   speedup has been lost — investigate before re-bumping the floor.

Both tests print the measured speedup. If a developer improves the Cython
path, both bars can be raised (and should be) to lock in the new
performance level.
"""
from __future__ import annotations

import sys
import timeit
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from brain.cython import build_engine, is_cython_available, scan_cython  # noqa: E402
from brain.windows_brain import (  # noqa: E402
    compile_tier2_rules,
    load_rules,
    run_regex_scan,
)

PAYLOAD = (
    "GET /login?user=admin' OR '1'='1&pass=foo HTTP/1.1\r\n"
    "Host: target.local\r\n"
    "User-Agent: sqlmap/1.5\r\n"
    "Accept: */*\r\n\r\n"
    "UNION SELECT username, password FROM users--\r\n"
)
ITERATIONS = 5_000  # per timeit repeat
REPEATS = 7  # timeit.repeat count
MIN_SPEEDUP = 1.10  # AC2: a real Cython conversion should beat this
REGRESSION_FLOOR = 1.05  # AC3: do not regress below this


def _measure_scan_cython() -> float:
    rules = load_rules()
    engine = build_engine(rules)
    # Warm up the regex cache.
    scan_cython(PAYLOAD, engine)
    t = timeit.repeat(
        lambda: scan_cython(PAYLOAD, engine),
        number=ITERATIONS,
        repeat=REPEATS,
    )
    return min(t)  # best-of-N for stability


def _measure_run_regex_scan() -> float:
    rules = load_rules()
    engine = compile_tier2_rules(rules)
    run_regex_scan(PAYLOAD, engine, rules)  # warm
    t = timeit.repeat(
        lambda: run_regex_scan(PAYLOAD, engine, rules),
        number=ITERATIONS,
        repeat=REPEATS,
    )
    return min(t)


def test_scan_cython_is_faster_than_pure_python() -> None:
    """AC2: the Cython re-implementation of the scan loop is faster."""
    # If Cython is not compiled, we cannot measure an actual speedup; the
    # `is_cython_available()` flag will gate this test in environments where
    # the extension is not built (e.g. lint-only CI). The pure-Python
    # fallback path is the AC4 evidence; the AC2 speedup test requires the
    # real C extension.
    assert is_cython_available(), (
        "brain.cython.cython_regex_scan is not compiled. Run:\n"
        "  cd brain/cython && python setup.py build_ext --inplace"
    )

    py_t = _measure_run_regex_scan()
    cy_t = _measure_scan_cython()
    speedup = py_t / cy_t

    print(
        f"\n  [T5b] scan_cython best-of-{REPEATS}: {cy_t*1e6/ITERATIONS:.3f} us/op "
        f"({ITERATIONS} ops, {cy_t:.3f}s total)"
    )
    print(
        f"  [T5b] run_regex_scan best-of-{REPEATS}: {py_t*1e6/ITERATIONS:.3f} us/op "
        f"({ITERATIONS} ops, {py_t:.3f}s total)"
    )
    print(f"  [T5b] measured speedup: {speedup:.2f}x  (AC2 floor: {MIN_SPEEDUP}x)")

    assert speedup >= MIN_SPEEDUP, (
        f"Expected Cython speedup >= {MIN_SPEEDUP}x, got {speedup:.2f}x. "
        f"pure_python={py_t:.3f}s  cython={cy_t:.3f}s"
    )


def test_speedup_is_above_regression_floor() -> None:
    """AC3: the speedup does not regress below the floor."""
    if not is_cython_available():
        # Without the Cython extension, the AC3 regression test is moot.
        # The pure-Python fallback is the AC4 evidence.
        import pytest
        pytest.skip("Cython extension not compiled; AC3 regression is N/A")

    py_t = _measure_run_regex_scan()
    cy_t = _measure_scan_cython()
    speedup = py_t / cy_t

    print(
        f"\n  [T5b regression] speedup = {speedup:.2f}x  (floor: {REGRESSION_FLOOR}x)"
    )
    assert speedup >= REGRESSION_FLOOR, (
        f"Speedup regression: {speedup:.2f}x is below the floor of {REGRESSION_FLOOR}x. "
        f"Investigate before re-bumping the floor."
    )
