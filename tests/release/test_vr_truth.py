"""P7/P8 verification/release truth pins (V&R-01..V&R-08).

Records-only E1/E2 guards. They stop a second build-source boundary, a
declared-only or out-of-order 24 h soak, stale component provenance, advisory
CI jobs labelled CANONICAL, superseded build-source labels, and a waiver being
reported as a green release from returning to current truth.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_release_freshness_uses_the_canonical_truth_boundary() -> None:
    final_audit = _load("final_audit_vr", "tools/final_audit.py")
    truth = _load("truth_vr", "tools/truth.py")
    assert final_audit.RUNTIME_PATHS == truth.SOURCE_PATHS
    assert "ts_policy" not in final_audit.RUNTIME_PATHS
    assert "configs" in final_audit.RUNTIME_PATHS
    assert "scripts/wdk_build_production.ps1" in final_audit.RUNTIME_PATHS


def test_soak_gate_requires_observed_elapsed_hours() -> None:
    final_audit = _load("final_audit_soak_vr", "tools/final_audit.py")
    base = {
        "path": "admin-evidence/x/soak-24h.json",
        "verdict": "PASS",
        "required_hours": 24.0,
        "problems": [],
        "soak_start": "2026-11-20T00:00:00",
        "checked_at": "2026-11-22T00:00:00",
        "stale": False,
    }
    short = final_audit.evaluate_soak([{**base, "elapsed_hours": 0.1}])
    assert short["ok"] is False
    assert "observed elapsed_hours" in short["detail"]
    assert "0.1/24.0 h" in short["detail"]

    missing = final_audit.evaluate_soak([base])
    assert missing["ok"] is False
    assert "observed elapsed_hours" in missing["detail"]

    valid = final_audit.evaluate_soak([{**base, "elapsed_hours": 24.4}])
    assert valid["ok"] is True


def test_soak_gate_requires_ordered_timestamps() -> None:
    final_audit = _load("final_audit_soak_times_vr", "tools/final_audit.py")
    base = {
        "path": "admin-evidence/x/soak-24h.json",
        "verdict": "PASS",
        "required_hours": 24.0,
        "elapsed_hours": 24.4,
        "problems": [],
        "soak_start": "2026-11-20T00:00:00",
        "checked_at": "2026-11-22T00:00:00",
        "stale": False,
    }
    assert final_audit.evaluate_soak([base])["ok"] is True

    missing_start = final_audit.evaluate_soak([{k: v for k, v in base.items()
                                               if k != "soak_start"}])
    assert missing_start["ok"] is False
    assert "soak_start/checked_at are missing" in missing_start["detail"]

    reversed_times = final_audit.evaluate_soak([{**base,
        "soak_start": "2026-11-23T00:00:00", "checked_at": "2026-11-22T00:00:00"}])
    assert reversed_times["ok"] is False
    assert "or out of order" in reversed_times["detail"]


def test_build_manifest_component_commits_match_source_commit() -> None:
    manifest = json.loads(_read("build_manifest.json"))
    source = manifest["source_commit"]
    assert source == "f1f89c1"
    assert manifest["components"], "expected component provenance"
    for component in manifest["components"]:
        assert component["commit"] == source, component["id"]

    ts = next(c for c in manifest["components"] if c["id"] == "ts-policy")
    assert ts["required"] is False
    assert ts["classification"] == "SUPPORT"
    assert "no runtime artifact" in ts["note"]


def test_refresh_restamps_component_commits(tmp_path, monkeypatch) -> None:
    mod = _load("release_engineering_vr", "tools/release_engineering.py")
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    manifest_path = tmp_path / "build_manifest.json"
    monkeypatch.setattr(mod, "MANIFEST_PATH", manifest_path)
    manifest_path.write_text(json.dumps({
        "source_commit": "old123",
        "components": [{"id": "core", "commit": "old123"}],
        "artifacts": [],
    }), encoding="utf-8")

    assert mod.refresh_digests("new456") == 0
    doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert doc["source_commit"] == "new456"
    assert doc["components"][0]["commit"] == "new456"


def test_refresh_docstring_no_longer_describes_removed_collector_rules() -> None:
    text = _read("tools/release_engineering.py")
    assert "HISTORICAL (V&R-04)" in text
    assert "lists the non-existent" not in text
    assert "picks up gitignored Cython" not in text


def test_advisory_ci_jobs_are_not_canonical_gates() -> None:
    coverage = json.loads(_read("ci_coverage.json"))
    by_id = {p["id"]: p for p in coverage["projects"]}
    ts = by_id["ts-policy"]
    scan = by_id["security-scan"]
    assert ts["required"] is False and ts["classification"] == "SUPPORT"
    assert "advisory" in ts["note"].lower()
    assert scan["required"] is False and scan["classification"] == "SUPPORT"
    assert "exit-code 0" in scan["note"]
    assert "triage SLA" in scan["note"]


def test_current_security_docs_carry_the_current_build_source() -> None:
    for rel in (
        "SECURITY.md",
        "docs/STRUCTURE.md",
        "docs/SECURITY_THREAT_MODEL.md",
        "docs/architecture/SECURITY_BOUNDARIES.md",
    ):
        text = _read(rel)
        assert "ab0fa17" not in text, rel
        assert "a26c573" in text, rel
