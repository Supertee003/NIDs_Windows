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


def _load_fresh_deploy():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "fresh_deploy", REPO / "tools" / "fresh_deploy.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_execute_aborts_at_first_failure() -> None:
    """Fail-closed orchestration: steps after a failure are SKIPPED and
    the exit code carries the failing step's rc (hermetic: python -c)."""
    mod = _load_fresh_deploy()
    fake = [
        ("s1", [sys.executable, "-c", "pass"], False),
        ("s2", [sys.executable, "-c", "import sys; sys.exit(3)"], True),
        ("s3", [sys.executable, "-c", "pass"], False),
    ]
    record, code = mod.execute(fake, plan=False)
    assert record["ok"] is False
    assert record["failed_step"] == "s2"
    assert code == 3
    by = {s["name"]: s for s in record["steps"]}
    assert by["s1"]["status"] == "OK"
    assert by["s2"]["status"] == "FAIL"
    assert by["s3"]["status"] == "SKIPPED"
