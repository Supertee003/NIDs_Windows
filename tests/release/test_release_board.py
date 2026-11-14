"""E2 pins for the release board (RELEASE-BOARD-001).

`tools/final_audit.py` used to print "100% PRODUCTION VERIFIED" for a complete
*component* audit. `RC-FINAL-20261114` recorded ~85% for the *release*, so one
command said 100% and a tracked record said 85% — the contradictory-source-of-
truth condition AGENTS.md forbids. The declaration is now split, and the release
half is computed from recorded artifacts.

These pins exist because every gate below can be faked by an artifact that merely
exists. Each test is a way a false ship verdict could be produced:

  * a complete component audit read as a shippable release,
  * a `signatures.json` reference record read as a signature,
  * a PASS from a hand-fixed lab host read as a clean install,
  * an IN_PROGRESS or 21 h soak read as a 24 h soak,
  * a PASS recorded before the current runtime commit read as current truth.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "final_audit.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("final_audit", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


TOOL_MOD = load_tool()
INSTALL = r"C:\Program Files\AEGIS NIDS"


def facts(**over) -> dict:
    base = {
        "truth": {"ok": True, "detail": "TRUTH_VALID"},
        "component": {"ok": True, "detail": "modules 66/66"},
        "signatures": [
            {
                "path": "release/T20-final/abc123/signatures.json",
                "signature": "MEUCIQ...",
                "public_key": "ed25519:AAA...",
                "algorithm": "ed25519",
                "signed_digest": "A" * 64,
                "actual_digest": "A" * 64,
            }
        ],
        "preflights": [
            {
                "path": "admin-evidence/e5/preflight-1.json",
                "verdict": "PASS",
                "failed": [],
                "loader": f'powershell.exe -File "{INSTALL}\\scripts\\boot-sequence.ps1"',
            }
        ],
        "soaks": [
            {
                "path": "admin-evidence/e5/soak-24h-1.json",
                "verdict": "PASS",
                "elapsed_hours": 24.4,
                "required_hours": 24.0,
                "problems": [],
                "checked_at": "2026-11-16T09:00:00",
                "stale": False,
            }
        ],
        "debt": {"unnamed": 528, "baseline": 528},
    }
    base.update(over)
    return base


def gates(**over) -> dict:
    return {g["id"]: g for g in TOOL_MOD.release_gates(facts(**over))}


def test_a_fully_evidenced_release_is_shippable() -> None:
    verdict = TOOL_MOD.release_verdict(TOOL_MOD.release_gates(facts()))
    assert verdict["shippable"] is True
    assert verdict["open"] == []


def test_a_complete_component_audit_alone_never_closes_the_release() -> None:
    """The exact defect: Part I/II/III green, nothing else recorded."""
    only_audit = facts(signatures=[], preflights=[], soaks=[])
    opened = gates(signatures=[], preflights=[], soaks=[])
    assert opened["component_audit"]["ok"] is True
    assert TOOL_MOD.release_verdict(
        TOOL_MOD.release_gates(only_audit)
    )["shippable"] is False
    assert {"release_signature", "clean_host_e5", "soak_24h"} <= {
        gid for gid, g in opened.items() if not g["ok"]
    }


def test_the_tool_can_no_longer_print_an_unqualified_100_percent_verdict() -> None:
    import ast

    source = TOOL.read_text(encoding="utf-8")
    tree = ast.parse(source)
    body = tree.body
    # The docstring explains the history; the executable body must not repeat
    # the claim. Drop the module docstring, then look at everything else.
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    code = "\n".join(ast.get_source_segment(source, node) or "" for node in body)
    assert "100% PRODUCTION VERIFIED" not in code, (
        "the component audit must not be declared as a whole-release verdict"
    )


def test_a_reference_record_is_not_a_signature() -> None:
    opened = gates(signatures=[{
        "path": "release/T20-final/46b93dc/signatures.json",
        "signature": None,
        "public_key": None,
        "algorithm": None,
        "signed_digest": None,
        "actual_digest": "B" * 64,
    }])
    gate = opened["release_signature"]
    assert gate["ok"] is False
    assert "reference record, not a signature" in gate["detail"]


def test_a_signature_over_the_wrong_digest_fails() -> None:
    opened = gates(signatures=[{
        "path": "release/x/signatures.json",
        "signature": "sig",
        "public_key": "key",
        "algorithm": "ed25519",
        "signed_digest": "A" * 64,
        "actual_digest": "C" * 64,
    }])
    gate = opened["release_signature"]
    assert gate["ok"] is False
    assert "SHA256SUMS hashes to" in gate["detail"]


def test_a_signature_without_the_sums_it_covers_fails() -> None:
    opened = gates(signatures=[{
        "path": "release/x/signatures.json",
        "signature": "sig",
        "public_key": "key",
        "algorithm": "ed25519",
        "signed_digest": "A" * 64,
        "actual_digest": None,
    }])
    assert opened["release_signature"]["ok"] is False


def test_a_lab_host_pass_does_not_close_the_clean_host_gate() -> None:
    opened = gates(preflights=[{
        "path": "admin-evidence/host-window-006/preflight-20261114.json",
        "verdict": "PASS",
        "failed": [],
        "loader": 'powershell.exe -File "D:\\NIDs_Windows\\admin-evidence\\bootstrap.ps1"',
    }])
    gate = opened["clean_host_e5"]
    assert gate["ok"] is False
    assert "outside the install directory" in gate["detail"]


def test_a_failed_preflight_names_the_open_check() -> None:
    opened = gates(preflights=[{
        "path": "admin-evidence/host-window-006/preflight-20261114.json",
        "verdict": "FAIL",
        "failed": ["boot_task_loader_installed"],
        "loader": 'powershell.exe -File "D:\\NIDs_Windows\\admin-evidence\\bootstrap.ps1"',
    }])
    gate = opened["clean_host_e5"]
    assert gate["ok"] is False
    assert "boot_task_loader_installed" in gate["detail"]


def test_an_in_progress_window_does_not_close_the_soak_gate() -> None:
    opened = gates(soaks=[{
        "path": "admin-evidence/host-window-006/soak-24h-delta-latest.json",
        "verdict": "IN_PROGRESS",
        "elapsed_hours": 2.04,
        "required_hours": 24.0,
        "problems": [],
        "checked_at": "2026-11-14T19:13:00",
        "stale": False,
    }])
    gate = opened["soak_24h"]
    assert gate["ok"] is False
    assert "IN_PROGRESS at 2.04/24.0 h" in gate["detail"]


def test_a_21_hour_pass_does_not_satisfy_a_24_hour_gate() -> None:
    opened = gates(soaks=[{
        "path": "admin-evidence/host-window-006/soak-21h-budget.json",
        "verdict": "PASS",
        "elapsed_hours": 21.77,
        "required_hours": 21.0,
        "problems": [],
        "checked_at": "2026-11-14T14:41:42",
        "stale": False,
    }])
    gate = opened["soak_24h"]
    assert gate["ok"] is False
    assert "no soak artifact declares a 24 h requirement" in gate["detail"]


def test_a_pass_older_than_the_runtime_commit_does_not_close_the_gate() -> None:
    opened = gates(soaks=[{
        "path": "admin-evidence/old/soak-24h.json",
        "verdict": "PASS",
        "elapsed_hours": 25.0,
        "required_hours": 24.0,
        "problems": [],
        "checked_at": "2026-10-01T00:00:00",
        "stale": True,
    }])
    gate = opened["soak_24h"]
    assert gate["ok"] is False
    assert "predates the current runtime source commit" in gate["detail"]


def test_unknown_soak_freshness_fails_closed() -> None:
    opened = gates(soaks=[{
        "path": "admin-evidence/x/soak-24h.json",
        "verdict": "PASS",
        "elapsed_hours": 25.0,
        "required_hours": 24.0,
        "problems": [],
        "checked_at": None,
        "stale": None,
    }])
    gate = opened["soak_24h"]
    assert gate["ok"] is False
    assert "freshness cannot be established" in gate["detail"]


def test_a_newest_failing_window_is_reported_even_when_an_older_pass_exists() -> None:
    opened = gates(soaks=[
        {
            "path": "admin-evidence/old/soak-24h-pass.json",
            "verdict": "PASS",
            "elapsed_hours": 25.0,
            "required_hours": 24.0,
            "problems": [],
            "checked_at": "2026-10-01T00:00:00",
            "stale": True,
        },
        {
            "path": "admin-evidence/new/soak-24h.json",
            "verdict": "FAIL",
            "elapsed_hours": 25.0,
            "required_hours": 24.0,
            "problems": ["daemon reports DEGRADED"],
            "checked_at": "2026-11-16T00:00:00",
            "stale": False,
        },
    ])
    gate = opened["soak_24h"]
    assert gate["ok"] is False
    assert "daemon reports DEGRADED" in gate["detail"]
    assert "older PASS" in gate["detail"]


def test_evidence_debt_growth_fails_and_unknown_debt_fails_closed() -> None:
    assert gates(debt={"unnamed": 529, "baseline": 528})["evidence_debt"]["ok"] is False
    assert gates(debt={"unnamed": None, "baseline": 528})["evidence_debt"]["ok"] is False
    assert gates(debt={"unnamed": 500, "baseline": 528})["evidence_debt"]["ok"] is True


def test_every_gate_has_an_owner_and_the_set_cannot_shrink() -> None:
    opened = gates()
    assert set(opened) == {
        "truth_artifacts",
        "component_audit",
        "release_signature",
        "clean_host_e5",
        "soak_24h",
        "evidence_debt",
    }
    assert all(g["owner"] in ("none", "owner", "time") for g in opened.values())


def test_truth_failure_opens_a_gate() -> None:
    opened = gates(truth={"ok": False, "detail": "TRUTH_STALE"})
    assert opened["truth_artifacts"]["ok"] is False
    assert "TRUTH_STALE" in opened["truth_artifacts"]["detail"]
