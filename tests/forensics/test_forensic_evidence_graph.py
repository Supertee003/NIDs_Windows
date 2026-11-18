"""FORENSIC-GRAPH-001: operator graphs must be derived from verified evidence only.

The retired threat-graph implementation rendered whatever it found in
`logs/aegis_core.ndjson`. The canonical implementation must instead query the
control daemon (`forensics list --json`) through the canonical CLI and must
refuse to produce any artifact unless the daemon reports an intact, verified
hash chain.

Contract pinned here:
  AC1. Records come from `tools/aegisctl.py forensics list --json` (canonical
       control path), never from a local log file; `--log` is retired.
  AC2. `available != true`                        => RuntimeError, no artifact.
  AC3. `integrity != "ok"` or `verified != true`  => RuntimeError, no artifact.
  AC4. A verified response renders the graph and reports the verified count.
  AC5. No tracked script still calls the removed `generate_threat_graph` API.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
GRAPH_SCRIPT = REPO_ROOT / "scripts" / "aegis_graph.py"

pytest.importorskip("networkx", reason="graph stack (networkx) not installed")
pytest.importorskip("pyvis", reason="graph stack (pyvis) not installed")


def _load_graph_module():
    spec = importlib.util.spec_from_file_location("aegis_graph_under_test", GRAPH_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fake_run(document: dict, *, captured: list | None = None, returncode: int = 0):
    def runner(command, **_kwargs):
        if captured is not None:
            captured.append(list(command))
        return subprocess.CompletedProcess(
            command, returncode, json.dumps(document), "" if returncode == 0 else "boom",
        )

    return runner


VERIFIED_RESPONSE = {
    "available": True,
    "records": [
        {
            "record_seq": 11,
            "event_id": 21,
            "rule_id": 7,
            "source": 3,
            "payload_len": 64,
            "verified": True,
        },
    ],
    "records_returned": 1,
    "integrity": "ok",
    "verified": True,
}


def test_query_uses_canonical_control_cli(monkeypatch):
    """AC1: the query targets tools/aegisctl.py forensics list, not a log file."""
    module = _load_graph_module()
    captured: list = []
    monkeypatch.setattr(module.subprocess, "run", _fake_run(VERIFIED_RESPONSE, captured=captured))

    module.query_forensic_records(5)

    assert len(captured) == 1
    command = captured[0]
    assert command[1].replace("\\", "/").endswith("tools/aegisctl.py")
    assert command[2:4] == ["forensics", "list"]
    assert "--json" in command
    assert "--log" not in command


def test_unavailable_control_plane_refuses_to_generate(monkeypatch, tmp_path):
    """AC2: no control daemon / no forensic ring => no graph artifact."""
    module = _load_graph_module()
    unavailable = {
        "available": False,
        "records": [],
        "records_returned": 0,
        "integrity": "unavailable",
        "verified": False,
    }
    monkeypatch.setattr(module.subprocess, "run", _fake_run(unavailable))

    output = tmp_path / "graph.html"
    with pytest.raises(RuntimeError, match="unavailable"):
        module.generate_forensic_graph(output, 10)
    assert not output.exists()


def test_unverified_hash_chain_refuses_to_generate(monkeypatch, tmp_path):
    """AC3: integrity failure or verified=false => no graph artifact."""
    module = _load_graph_module()
    tampered = dict(VERIFIED_RESPONSE, integrity="failed", verified=False)
    monkeypatch.setattr(module.subprocess, "run", _fake_run(tampered))

    output = tmp_path / "graph.html"
    with pytest.raises(RuntimeError, match="not verified"):
        module.generate_forensic_graph(output, 10)
    assert not output.exists()


def test_verified_evidence_renders_graph(monkeypatch, tmp_path):
    """AC4: verified records render an evidence graph and report the count."""
    module = _load_graph_module()
    monkeypatch.setattr(module.subprocess, "run", _fake_run(VERIFIED_RESPONSE))

    output = tmp_path / "graph.html"
    records, nodes, edges = module.generate_forensic_graph(output, 10)

    assert records == 1
    assert nodes >= 5 and edges >= 4
    html = output.read_text(encoding="utf-8", errors="replace")
    assert "AEGIS Forensic Evidence Graph" in html
    assert "Record 11" in html


def test_retired_log_flag_is_rejected():
    """AC1: `--log` must fail loudly instead of silently reading a file."""
    completed = subprocess.run(
        [sys.executable, str(GRAPH_SCRIPT), "--log", "logs/aegis_core.ndjson"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    assert completed.returncode != 0
    assert "retired" in (completed.stderr + completed.stdout)


def test_no_script_uses_removed_threat_graph_api():
    """AC5: the removed `generate_threat_graph` name must not survive in code."""
    scanned = 0
    for base in ("scripts", "tools"):
        for path in sorted((REPO_ROOT / base).rglob("*.py")):
            parts = set(path.relative_to(REPO_ROOT).parts)
            if parts & {"__pycache__", "legacy", "node_modules"}:
                continue
            scanned += 1
            assert "generate_threat_graph" not in path.read_text(encoding="utf-8", errors="replace"), (
                f"{path.relative_to(REPO_ROOT)} still calls the removed threat-graph API"
            )
    assert scanned > 0
    assert "def generate_forensic_graph" in GRAPH_SCRIPT.read_text(encoding="utf-8")
