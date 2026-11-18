"""CI-GATE-107: CI enforces truth stamps and pins its supply chain.

Failure mode pinned: the pre-commit checklist demands `truth.py
verify`, but CI never ran it (a stale-map commit passed the pipeline),
and the Trivy step floated on `@master` (a moving supply-chain ref).
Contract:

  AC1. The python-tests job runs `truth.py verify` after the
       provenance gate (fail-fast on stale maps, same as pre-commit).
  AC2. No workflow step floats on `@master`/`@main`; the Trivy action
       is pinned to a released tag, and its non-blocking status is a
       documented decision (needs a triage SLA to enforce), not drift.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _workflow() -> str:
    return CI.read_text(encoding="utf-8")


def test_truth_verify_gate_runs_in_ci():
    text = _workflow()
    assert "python tools/truth.py verify" in text
    assert text.index("release_engineering.py --verify") < text.index("python tools/truth.py verify")


def test_no_floating_action_refs():
    text = _workflow()
    assert "trivy-action@master" not in text
    # Only `uses:` lines may carry refs; comments mention @master to
    # explain the pin and must not trip the check.
    uses = [line for line in text.splitlines() if "uses:" in line]
    assert uses, "expected at least one uses: step"
    for line in uses:
        assert "@master" not in line and "@main" not in line, line.strip()


def test_trivy_pin_is_a_release_tag():
    import re

    text = _workflow()
    # trivy-action migrated its tags to the `v` prefix (v0.36.0); the
    # unprefixed 0.36.0 tag does not exist and made the job unresolvable.
    assert re.search(r"trivy-action@v0\.36\.0", text), "Trivy must stay pinned to a verified release"
    assert "exit-code: 0" in text


# =====================================================================
# CI-GAPS (2026-10-19): jobs that deep scan §9 found missing, and the
# gate wiring that must actually evaluate the required ones.
# =====================================================================
import json  # noqa: E402
import re  # noqa: E402

COVERAGE = REPO_ROOT / "ci_coverage.json"
HOST_REGRESSION = REPO_ROOT / ".github" / "workflows" / "host-regression.yml"

_JOB_KEY = r"^  {job}:\s*$"
_ANY_JOB_KEY = r"^  [A-Za-z0-9_-]+:\s*$"


def _job_block(job_id: str, workflow: Path = CI) -> str:
    """Text of one top-level job block (indent-2 key) in a workflow file.

    Deliberately dependency-free: the repo declares pyyaml, but the dev
    venv this pin runs in did not have it installed -- a structural pin
    must not turn into a skip/error on a valid environment.
    """
    text = workflow.read_text(encoding="utf-8")
    match = re.search(_JOB_KEY.format(job=re.escape(job_id)), text, re.M)
    assert match, f"job {job_id!r} not declared in {workflow.name}"
    rest = text[match.end():]
    nxt = re.search(_ANY_JOB_KEY, rest, re.M)
    return rest[: nxt.start()] if nxt else rest


def _job_ids(workflow: Path) -> set[str]:
    text = workflow.read_text(encoding="utf-8")
    jobs_part = text[text.index("\njobs:"):] if "\njobs:" in text else text
    return {m.group(1) for m in re.finditer(r"^  ([A-Za-z0-9_-]+):\s*$", jobs_part, re.M)}


def _gate_needs(gate: str) -> set[str]:
    match = re.search(r"needs:\s*\[([^\]]*)\]", _job_block(gate))
    assert match, (
        f"{gate}.needs must be an inline list for this pin to evaluate it "
        "-- if the workflow switched to block style, update the parser"
    )
    return {name.strip() for name in match.group(1).split(",") if name.strip()}


def _coverage() -> dict:
    return json.loads(COVERAGE.read_text(encoding="utf-8"))


def test_brain_suite_and_accelerator_are_separately_gated():
    """CI-GAPS: brain/test_*.py ran nowhere (pytest targeted tests/ only)
    and brain/aegis_brain_cython -- the accelerator the production host
    ships as fast_scan.cp3xx-win_amd64.pyd -- was never built or tested,
    so its pure-Python fallback silently masked the real configuration."""
    brain = _job_block("brain-tests")
    assert "pytest brain/" in brain, (
        "brain-tests must run the brain-local suite (pytest brain/)"
    )

    cython = _job_block("cython-build-test")
    assert "brain/aegis_brain_cython" in cython, "must build the shipped accelerator package"
    assert "build_ext --inplace" in cython
    assert "test_fast_scan.py" in cython, "must run the accelerator unit suite"
    assert "tests/brain/test_cython_prefilter.py" in cython, (
        "must run the Case-2 pre-filter pin in the accelerated configuration"
    )
    assert "aegis_hotspot" not in cython, (
        "the retired brain/cython/aegis_hotspot module must not be built here: "
        "the T5b regex accelerator keeps its build inside python-tests"
    )


def test_operator_tool_jobs_build_and_test_the_real_manifests():
    """CI-GAPS: mouth and aegis_dashboard had no build gate at all."""
    mouth = _job_block("mouth-build-test")
    assert "cargo test --manifest-path mouth/Cargo.toml" in mouth
    assert "cargo build --release --manifest-path mouth/Cargo.toml" in mouth

    dash = _job_block("dashboard-build-test")
    assert "cargo test --manifest-path aegis_dashboard/Cargo.toml" in dash
    assert "cargo build --release --manifest-path aegis_dashboard/Cargo.toml" in dash


def test_drivers_job_is_manual_only_until_a_run_is_verified():
    """The WDK build cannot be PR-gated yet: needs WDK + test-signing, and
    no hosted run has been observed green. A manual job keeps the driver
    sources under bit-rot watch without adding an unverified red signal."""
    drivers = _job_block("drivers-wdk-build")
    cond = re.search(r"^    if:\s*(.+)$", drivers, re.M)
    assert cond, "drivers job must declare a top-level `if:`"
    assert "workflow_dispatch" in cond.group(1), (
        "drivers job must be manual-only (workflow_dispatch) until verified"
    )
    assert "build_drivers.bat" in drivers


def test_every_required_coverage_project_reaches_the_gate():
    """A required project whose job never reaches the gate's `needs` map
    can not be evaluated: check_results only sees jobs present in the
    needs payload, and the pipeline would stay green without it.
    Live example of the wiring drift class: the shield entry carried an
    empty job id while the workflow already built it. This pin closes the
    class for anything the matrix marks required."""
    coverage = _coverage()
    gate = coverage["gate_job"]
    gate_needs = _gate_needs(gate)
    missing = [
        p["job"] for p in coverage["projects"]
        if p.get("required") and p.get("job") and p["job"] != gate
        and p["job"] not in gate_needs
    ]
    assert not missing, f"required projects absent from {gate}.needs: {missing}"


def test_coverage_entries_reference_real_jobs_or_explain_the_gap():
    coverage = _coverage()
    job_ids = _job_ids(CI) | _job_ids(HOST_REGRESSION)
    for p in coverage["projects"]:
        if p.get("job"):
            assert p["job"] in job_ids, f"{p['id']}: job {p['job']!r} is in no workflow"
        else:
            assert p.get("note"), f"{p['id']}: empty job with no documented reason"


def test_coverage_matrix_records_the_new_reality():
    by_id = {p["id"]: p for p in _coverage()["projects"]}
    assert by_id["brain"]["job"] == "brain-tests"
    assert by_id["brain"]["required"] is True
    assert by_id["cython-scan"]["job"] == "cython-build-test"
    assert by_id["cython-scan"]["required"] is True
    note = by_id["cython-scan"].get("note", "")
    assert "built inside python-tests" not in note, "stale claim: that step builds brain/cython"
    assert "aegis_brain_cython" in note
    assert by_id["shield"]["job"] == "shield-build", "shield's job exists and must be named"
    assert by_id["shield"]["required"] is False, (
        "shield is an advisory-only, fail-safe-loadable helper: the job runs but never gates"
    )
    for pid in ("mouth", "aegis-dashboard", "drivers"):
        assert by_id[pid]["required"] is False, f"{pid} is a non-gating report"
    assert by_id["drivers"].get("note")
    assert not by_id["e2e"].get("job"), "e2e stays a documented decision, not a green-wash job"
    assert by_id["e2e"].get("note")
