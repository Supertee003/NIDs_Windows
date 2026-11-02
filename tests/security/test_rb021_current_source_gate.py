from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = ROOT / "scripts" / "rb021_current_source_preflight.ps1"
WRAPPER = ROOT / "scripts" / "run_wfp_hostonly_observe_only.ps1"
RUNBOOK = ROOT / "docs" / "runbooks" / "RB-021-hostonly-lab-proof.md"


def test_rb021_preflight_is_current_source_and_detection_only():
    text = PREFLIGHT.read_text(encoding="utf-8")
    assert "RB021_PREFLIGHT_PASS" in text
    assert "RB021_PREFLIGHT_BLOCKED" in text
    assert "installed_matches_current_build" in text
    assert "build_manifest_source" in text
    assert "host_effect_confirmed = $false" in text
    assert "prevention_gate = 'closed'" in text
    assert "safe.directory=$repo" in text
    assert "exit 2" in text


def test_rb021_wrapper_cannot_start_current_source_proof_without_gate():
    text = WRAPPER.read_text(encoding="utf-8")
    assert "RequireCurrentSource" in text
    assert "rb021_current_source_preflight.ps1" in text
    assert "stopped before canary" in text


def test_rb021_runbook_distinguishes_e1_preflight_from_e5():
    text = RUNBOOK.read_text(encoding="utf-8")
    assert "not E5-complete" in text
    assert "Only `RB021_PREFLIGHT_PASS` permits the canary phase." in text
    assert "Do not use a bypass switch" in text
