"""
T5b profile: identify the real Python hotspot in the AEGIS Brain before any
Cython conversion.

Per the T5b acceptance criteria, a profile must identify a real Python hotspot
BEFORE any Cython re-implementation. This script does that for the canonical
hot loop `run_regex_scan` in `brain/windows_brain.py`.

Run from repo root:
    python tests/cython/profile_brain_hotspot.py [--iterations N] [--payload HTTP_SQLI]

Outputs:
  - stdout: top-15 cumulative time hotspots
  - tests/cython/PROFILE_REPORT.md: human-readable summary committed to the repo
"""
from __future__ import annotations

import argparse
import cProfile
import io
import json
import os
import pstats
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from brain.windows_brain import (  # noqa: E402  (after sys.path mutation)
    compile_tier2_rules,
    load_rules,
    run_regex_scan,
)

DEFAULT_RULES = REPO_ROOT / "config" / "Rules.json"
DEFAULT_PAYLOAD = (
    b"GET /login?user=admin' OR '1'='1&pass=foo HTTP/1.1\r\n"
    b"Host: target.local\r\n"
    b"User-Agent: Mozilla/5.0 (compatible) sqlmap/1.5\r\n"
    b"Accept: */*\r\n\r\n"
    b"UNION SELECT username, password FROM users--\r\n"
)


def build_workload(iterations: int):
    """Yield a list of (payload, engine, rules) tuples for profiling."""
    rules = load_rules()
    engine = compile_tier2_rules(rules)
    return [(DEFAULT_PAYLOAD, engine, rules)] * iterations, rules, engine


def run_profile(iterations: int, top_n: int) -> tuple[str, dict]:
    """Run cProfile on run_regex_scan; return (formatted_text, stats_dict)."""
    workload, rules, engine = build_workload(iterations)

    profiler = cProfile.Profile()
    profiler.enable()
    matches = 0
    for payload, eng, rs in workload:
        if run_regex_scan(payload, eng, rs) is not None:
            matches += 1
    profiler.disable()

    stream = io.StringIO()
    stats = pstats.Stats(profiler, stream=stream).sort_stats(pstats.SortKey.CUMULATIVE)
    stats.print_stats(top_n)

    summary = {
        "iterations": iterations,
        "matches": matches,
        "rules_loaded": len(rules.get("nids_rules", [])),
        "engine_size": len(engine),
    }
    return stream.getvalue(), summary


def render_report(profile_text: str, summary: dict) -> str:
    return (
        "# T5b Profile Report — `run_regex_scan` Hot Path\n\n"
        f"- iterations: **{summary['iterations']}**\n"
        f"- rules loaded: **{summary['rules_loaded']}**\n"
        f"- compiled engine size: **{summary['engine_size']}** patterns\n"
        f"- matches: **{summary['matches']}**\n"
        f"- payload: synthetic HTTP request with SQL injection + UNION SELECT\n\n"
        "## Top cumulative-time hotspots\n\n"
        "```\n" + profile_text + "```\n\n"
        "## Conclusion\n\n"
        "This profile is the AC1 evidence for T5b: a measurement-driven identification "
        "of the real Python hotspot. See `test_cython_profile.py` for the locked-in "
        "assertion that the hotspot is where we expected it (the `re.search` loop in "
        "`run_regex_scan`), and `test_cython_regression.py` for the locked-in speedup.\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--top", type=int, default=15)
    parser.add_argument(
        "--out", type=Path, default=REPO_ROOT / "tests" / "cython" / "PROFILE_REPORT.md"
    )
    args = parser.parse_args()

    text, summary = run_profile(args.iterations, args.top)
    report = render_report(text, summary)
    args.out.write_text(report, encoding="utf-8")

    # Print the top-5 lines so the commit log carries the headline.
    print(report.splitlines()[0])
    print(report.splitlines()[1])
    print(f"  iterations={summary['iterations']}  matches={summary['matches']}  "
          f"rules={summary['rules_loaded']}  engine_size={summary['engine_size']}")
    print(f"  full report: {args.out}")
    print()
    for line in text.splitlines()[: min(args.top, 12)]:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
