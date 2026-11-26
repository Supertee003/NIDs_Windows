#!/usr/bin/env python3
"""Detection-chain health demo (EVT-175): prove every provable link.

Fires exactly ONE marked canary (AEGIS_FIXTURE payload, TEST rule id --
never confusable with real incidents), then proves what the current
retrieval surface allows: transport accepted, daemon alive and flowing,
ring appending with integrity true, graph rebuilt. It does NOT claim
per-event attribution: ring responses carry no payload text and search
has no rule filter, so one marked event cannot be picked out of
background flow on a busy host (see GAP-019). That boundary is printed,
not hidden -- a demo that pretends otherwise would be a lie.

Side effects, stated plainly: one marked record enters the pipeline
(same sanctioned gate-E pattern as `test golden-path`).
Nothing else mutates. --dry-run prints the plan and touches nothing.

Exit codes: 0 chain healthy (with the attribution caveat) | 1 fire
failed | 2 ring stalled/unhealthy | 3 graph failed.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GEN = REPO_ROOT / "scripts" / "aegis_event_gen.py"
CLI = REPO_ROOT / "tools" / "aegisctl.py"
MARKER = "AEGIS_FIXTURE"


def _run(argv, timeout: int = 120):
    try:
        proc = subprocess.run(
            [sys.executable, *[str(a) for a in argv]],
            cwd=str(REPO_ROOT), capture_output=True, text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)


def _ring_tip():
    rc, out, _ = _run([CLI, "forensics", "list", "--json"], timeout=90)
    if rc != 0:
        return None
    try:
        tip = json.loads(out).get("next_after")
        return int(tip) if tip is not None else None
    except (ValueError, TypeError):
        return None


def _nose_flowing():
    rc, out, _ = _run([CLI, "metrics", "--compact"], timeout=90)
    if rc != 0:
        return False
    try:
        return int(json.loads(out).get("packets_captured", 0) or 0) > 0
    except (ValueError, TypeError):
        return False


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Prove the detection chain link by link (marked canary).")
    parser.add_argument("--fixture", default="xss",
                        choices=["xss", "path-traversal", "command-injection"])
    parser.add_argument("--graph-out", default=None,
                        help="Graph HTML path (default reports/threat_graph.html)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the plan; fire nothing, touch nothing")
    args = parser.parse_args(argv)

    plan = [
        "1. fire:   aegis_event_gen.py --pipe --fixture %s --count 1 (ONE marked event)" % args.fixture,
        "2. flow:   daemon alive + nose flowing (nothing stalled mid-demo)",
        "3. ring:   tip advances + forensic verify true (appending, intact)",
        "4. graph:  aegisctl graph rebuilt from the current log",
        "   NOTE: per-event attribution is unavailable (GAP-019): the chain",
        "   below proves health, not that this one event matched a rule.",
    ]
    if args.dry_run:
        print("\n".join(plan))
        print("dry run: nothing fired, nothing touched")
        return 0

    print(plan[0], flush=True)
    rc, _, err = _run([GEN, "--pipe", "--fixture", args.fixture, "--count", "1"],
                      timeout=120)
    if rc != 0:
        print("FIRE FAILED: %s" % err.strip()[:200])
        return 1
    print("SENT: transport accepted (pipe write OK)", flush=True)

    print(plan[1], flush=True)
    tip_before = _ring_tip()
    flowing_before = _nose_flowing()
    if tip_before is None or not flowing_before:
        print("FLOW CHECK FAILED: daemon/ring unreadable mid-demo")
        return 2

    print(plan[2], flush=True)
    time.sleep(10)
    tip_after = _ring_tip()
    rc, out, _ = _run([CLI, "forensic", "verify"], timeout=120)
    try:
        verified = rc == 0 and json.loads(out).get("verified") is True
    except ValueError:
        verified = False
    advanced = tip_after is not None and tip_before is not None and tip_after > tip_before
    print("RING: tip %s -> %s (%s), integrity %s" % (
        tip_before, tip_after, "advanced" if advanced else "STALLED",
        "verified" if verified else "NOT verified"))
    if not advanced or not verified:
        return 2

    print(plan[3], flush=True)
    graph_argv = [CLI, "graph", "--limit", "300"]
    if args.graph_out:
        graph_argv += ["--out", args.graph_out]
    rc, out, err = _run(graph_argv, timeout=300)
    if rc != 0:
        print("GRAPH FAILED: %s" % err.strip()[:200])
        return 3
    print(out.strip().splitlines()[0] if out.strip() else "graph built")
    print("CHAIN HEALTHY: transport + flow + appending ring + graph.")
    print("Attribution boundary (GAP-019): per-event proof needs a rule")
    print("filter the ring does not have; this demo does not fake it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
