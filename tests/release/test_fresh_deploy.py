"""DEPLOY-117: fresh_deploy --plan is green and side-effect free.

STEP 50 closure pins: the plan runs read-only steps live against the
canonical tools, defers mutating steps, and must not create, modify, or
delete any tree state (verified via git status --porcelain before/after).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "tools/fresh_deploy.py", *args],
        cwd=str(REPO), capture_output=True, text=True, timeout=600,
    )


def test_plan_lists_five_ordered_steps() -> None:
    p = _run("--plan", "--json")
    assert p.returncode == 0, p.stderr[-2000:]
    rec = json.loads(p.stdout)
    assert rec["mode"] == "plan"
    assert rec["ok"] is True
    assert [s["name"] for s in rec["steps"]] == [
        "preflight", "validate", "snapshot", "package", "report",
    ]


def test_plan_defers_mutating_steps_and_runs_readonly() -> None:
    p = _run("--plan", "--json")
    assert p.returncode == 0, p.stderr[-2000:]
    by = {s["name"]: s for s in json.loads(p.stdout)["steps"]}
    assert by["snapshot"]["status"] == "DEFERRED"
    assert by["package"]["status"] == "DEFERRED"
    for name in ("preflight", "validate", "report"):
        assert by[name]["status"] == "OK", (name, by[name])


def test_plan_writes_nothing() -> None:
    def porcelain() -> str:
        return subprocess.run(
            ["git", "status", "--porcelain"], cwd=str(REPO),
            capture_output=True, text=True, timeout=60,
        ).stdout
    before = porcelain()
    p = _run("--plan")
    assert p.returncode == 0, p.stderr[-2000:]
    assert porcelain() == before
