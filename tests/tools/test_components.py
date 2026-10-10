"""EVT-162: the five AEGIS components render as concepts of their own.

Covers the shared registry (tools/aegisctl/components.py) that the CLI,
the web console, and the terminal watch all render:
  - the registry holds exactly the five concepts with identity fields
    (name, language, role, version, entrypoint, required);
  - versions match `aegisctl version` (single truth, cross-pinned);
  - status never claims "running" without evidence (empty health ->
    unknowns, never false-green);
  - the fast path (web/watch hot loop) spawns NO subprocess;
  - deep probes are deterministic under mocks.

No tree writes. The subprocess tests are read-only CLI runs.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from tools.aegisctl import components as compmod
from tools.aegisctl.components import COMPONENTS, components_status


def test_registry_holds_the_five_concepts():
    assert [c["id"] for c in COMPONENTS] == ["core", "brain", "nose", "mouth", "bridge"]
    langs = {c["id"]: c["language"] for c in COMPONENTS}
    assert langs == {"core": "Zig", "brain": "Python", "nose": "Go",
                     "mouth": "Rust", "bridge": "C++"}
    for comp in COMPONENTS:
        for key in ("id", "name", "language", "role", "owns",
                    "version", "entrypoint"):
            assert comp[key], (comp["id"], key)
        assert isinstance(comp["required"], bool), comp["id"]
    assert [c["name"] for c in COMPONENTS] == [
        "AEGIS Core", "AEGIS Brain", "AEGIS Nose", "AEGIS Mouth", "AEGIS Bridge"]
    assert COMPONENTS[3]["required"] is False  # mouth is an optional display
    assert all(c["required"] is True for c in COMPONENTS[:3] + COMPONENTS[4:])


def test_versions_match_aegisctl_version():
    # Single truth: the registry constants must equal the CLI table.
    proc = subprocess.run(
        [sys.executable, "tools/aegisctl.py", "version"],
        cwd=str(REPO), capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    table = {}
    for line in proc.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) == 2:
            table[parts[0]] = parts[1]
    for cid in ("core", "nose", "brain", "bridge"):
        reg = next(c for c in COMPONENTS if c["id"] == cid)
        assert table[cid] == reg["version"], cid


def test_status_never_claims_running_without_evidence():
    rows = components_status({})
    assert [r["id"] for r in rows] == ["core", "brain", "nose", "mouth", "bridge"]
    for row in rows:
        assert row["status"] in ("running", "stopped", "degraded", "unknown")
        assert row["status"] != "running", row["id"]
    rows = components_status(None)
    assert all(r["status"] != "running" for r in rows)


def test_fast_path_spawns_no_subprocess():
    # The web snapshot rebuilds every few seconds: any spawn here would
    # reintroduce the pipe/process churn EVT-149 removed. Fail loudly.
    def _boom(*args, **kwargs):
        raise AssertionError("fast path must not probe")
    health = {"state": "RUNNING", "data_plane": {"nose_frames_read": 10},
              "capabilities": {"cpp_bridge": True}}
    with patch.object(compmod, "_ps_output", side_effect=_boom), \
         patch.object(compmod, "bridge_diagnostic", side_effect=_boom):
        rows = components_status(health, deep=False)
    assert len(rows) == 5
    assert next(r for r in rows if r["id"] == "core")["status"] == "running"
    assert next(r for r in rows if r["id"] == "nose")["status"] == "running"


def test_deep_probes_deterministic_under_mocks():
    health = {"state": "RUNNING", "data_plane": {"nose_frames_read": 7},
              "capabilities": {}}
    with patch.object(compmod, "_service_running", return_value=True), \
         patch.object(compmod, "_proc_running", side_effect=[True, False]), \
         patch.object(compmod, "bridge_diagnostic",
                      return_value={"owner_is_brain": True, "secret_posture": "on",
                                    "listener": {"pid": 1}}):
        rows = {r["id"]: r for r in components_status(health, deep=True)}
    assert rows["core"]["status"] == "running"
    assert rows["nose"]["status"] == "running"  # frames>0 wins over probe order
    assert rows["brain"]["status"] == "running"
    assert "(auth on)" in rows["brain"]["detail"]
    assert rows["mouth"]["status"] == "stopped"  # second _proc_running -> False
