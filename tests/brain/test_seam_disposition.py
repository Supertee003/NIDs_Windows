"""LEFTOVER-SWEEP (2026-10-19): Tier-2 seam modules stay test-bound, visibly.

brain/ has one production entrypoint (brain/windows_brain.py, the file the
runtime spawns). The 2026-10-19 deep scan flagged ten brain modules as
"unwired": they are the typed Phase-5..10 seams (enforcement/IPS boundary,
readiness gates, the Python wire codec) that are exercised only by brain
tests - they are NOT imported by the production entrypoint.

This pin mechanizes the disposition:

  1. the import closure of brain/windows_brain.py (static AST edges over
     top-level brain/*.py modules) must equal the module set minus the
     registered seam-only list below - an eleventh unwired module fails
     loudly, and a seam that gets wired into the entrypoint also fails
     loudly (then move it out of this registry);
  2. every registered seam module must carry the explicit status marker
     ``SEAM-STATUS: not wired to the production entrypoint`` so the fact
     is visible at the source site, not only in this test;
  3. wired modules must not carry the marker.

Read-only: no tree writes.
"""
from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BRAIN = REPO_ROOT / "brain"
ENTRYPOINT = "windows_brain"

SEAM_ONLY: dict[str, str] = {
    "acceptance_gates": "Phase 8-10 readiness gates (harness fixture)",
    "canonical_event": "Python Plane-C wire codec binding (analytics side)",
    "core_routing": "Phase 5-7 detection -> Tier-3 routing seam",
    "tier_routing": "policy-neutral routing for DetectionResult",
    "enforcement_pipeline": "receipt-first enforcement seam (alert-only)",
    "pep_request": "policy-authority-bound PEP request adapter",
    "pep_receipt": "PEP response -> EnforcementReceipt mapping",
    "enforcement_receipt": "versioned alert-only receipt boundary",
    "policy_decision": "alert-only policy adapter",
    "forensic_evidence": "receipt-backed forensic evidence envelope",
}

SEAM_MARKER = "SEAM-STATUS: not wired to the production entrypoint"


def _modules() -> dict[str, Path]:
    return {
        p.stem: p
        for p in sorted(BRAIN.glob("*.py"))
        if not p.stem.startswith("test_") and p.stem != "__init__"
    }


def _imported_brain_names(path: Path, universe: set[str]) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.split(".")[-1])
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[-1])
    return {n for n in names if n in universe and n != path.stem}


def _production_closure() -> set[str]:
    modules = _modules()
    universe = set(modules)
    edges = {name: _imported_brain_names(p, universe) for name, p in modules.items()}
    assert ENTRYPOINT in edges, "brain/windows_brain.py is missing - entrypoint moved?"
    closure = {ENTRYPOINT}
    frontier = [ENTRYPOINT]
    while frontier:
        current = frontier.pop()
        for nxt in edges[current] - closure:
            closure.add(nxt)
            frontier.append(nxt)
    return closure


def test_unwired_set_is_exactly_the_registered_seams():
    modules = set(_modules())
    closure = _production_closure()
    unwired = modules - closure
    assert unwired == set(SEAM_ONLY), (
        f"brain module disposition drifted. Newly unwired (register or wire): "
        f"{sorted(unwired - set(SEAM_ONLY))}; wired since (drop from registry): "
        f"{sorted(set(SEAM_ONLY) - unwired)}"
    )


def test_every_registered_seam_carries_the_status_marker():
    for name in sorted(SEAM_ONLY):
        text = (BRAIN / f"{name}.py").read_text(encoding="utf-8")
        assert SEAM_MARKER in text, (
            f"brain/{name}.py lacks the visible status marker: {SEAM_MARKER!r} "
            f"({SEAM_ONLY[name]})"
        )


def test_wired_modules_do_not_carry_the_seam_marker():
    for name in sorted(_production_closure()):
        text = (BRAIN / f"{name}.py").read_text(encoding="utf-8")
        assert SEAM_MARKER not in text, (
            f"brain/{name}.py is wired to the production entrypoint but carries "
            f"the seam marker; remove the marker"
        )
