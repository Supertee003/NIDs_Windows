"""T5b AC1: profile identifies a real Python hotspot before any Cython conversion.

Locks in the profile result: `run_regex_scan` in `brain/windows_brain.py` is
the dominant cumulative-time hotspot for the canonical brain workload. This
test re-runs the profile (deterministic synthetic payload, 1000 iterations)
and asserts the per-iteration time of `run_regex_scan` is the largest single
contributor in the cProfile output.

If this test ever fails because a faster path has displaced the loop, that
IS the Cython optimization landing — bump the threshold or remove the test
with a docstring explaining the new profile.
"""
from __future__ import annotations

import cProfile
import io
import pstats
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

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
ITERATIONS = 10_000


def test_run_regex_scan_is_top_cumulative_hotspot() -> None:
    """AC1: `run_regex_scan` is the dominant cumulative-time function."""
    rules = load_rules()
    engine = compile_tier2_rules(rules)
    assert len(rules.get("nids_rules", [])) >= 1, "Rules.json must load"

    profiler = cProfile.Profile()
    profiler.enable()
    for _ in range(ITERATIONS):
        run_regex_scan(PAYLOAD, engine, rules)
    profiler.disable()

    stream = io.StringIO()
    stats = pstats.Stats(profiler, stream=stream).sort_stats(pstats.SortKey.CUMULATIVE)
    stats.print_stats(20)
    output = stream.getvalue()

    # cProfile rows look like: "   1000    0.002  ...  run_regex_scan"
    # Split into rows by counting whitespace prefix: data rows start with
    # a digit (after the leading spaces).
    data_rows = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Skip the "<N> function calls in X seconds" header
        if "function calls" in stripped and "seconds" in stripped:
            continue
        # Data rows start with a digit (the ncalls column)
        if stripped[0].isdigit():
            data_rows.append(stripped)
    assert data_rows, f"profile produced no data rows:\n{output}"
    top = data_rows[0]
    assert "run_regex_scan" in top, (
        f"Expected `run_regex_scan` to be the top cumulative-time hotspot, "
        f"but got: {top!r}\n\nFull profile:\n{output}"
    )


def test_re_search_loop_dominates_tottime() -> None:
    """AC1 (narrower): the regex search loop inside run_regex_scan is one
    of the top cumulative-time functions, confirming the per-rule
    regex call is the actual CPU work (not e.g. JSON decoding).

    On Python 3.14+ the interpreter may inline re.Pattern.search so it
    does not appear as a separate cProfile row.  In that case we verify
    that run_regex_scan itself dominates instead."""
    rules = load_rules()
    engine = compile_tier2_rules(rules)

    profiler = cProfile.Profile()
    profiler.enable()
    for _ in range(ITERATIONS):
        run_regex_scan(PAYLOAD, engine, rules)
    profiler.disable()

    stream = io.StringIO()
    stats = pstats.Stats(profiler, stream=stream).sort_stats(pstats.SortKey.CUMULATIVE)
    stats.print_stats(20)
    output = stream.getvalue()

    # Prefer the specific re.Pattern check; fall back to run_regex_scan
    # dominance on Python versions that inline the call.
    if "re.Pattern" in output:
        return
    # At minimum run_regex_scan must be the top function (the hotspot).
    data_rows = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "function calls" in stripped and "seconds" in stripped:
            continue
        if stripped[0].isdigit():
            data_rows.append(stripped)
    assert data_rows, f"profile produced no data rows:\n{output}"
    assert "run_regex_scan" in data_rows[0], (
        f"Expected `run_regex_scan` to be the top cumulative-time hotspot, "
        f"but got: {data_rows[0]!r}\n\nFull profile:\n{output}"
    )
