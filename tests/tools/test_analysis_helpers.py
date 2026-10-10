"""EVT-166: repaired analysis helpers stay green (read-only runs).

analyze_vectors was rewritten for the descriptor-table schema,
analyze_existing retired to it, check_evidence and read_vectors fixed
(UTF-8, real paths, PYEOF removed). Each runs in seconds with no system
touch: assert exit 0 plus a content marker so silent empty-output
regressions fail loudly. CWD is the repo root (relative paths by design).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _run(name: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "scripts/%s" % name],
        cwd=str(REPO), capture_output=True, text=True, timeout=120,
    )
    return proc.returncode, proc.stdout


def test_analyze_vectors_dumps_descriptor_table():
    rc, out = _run("analyze_vectors.py")
    assert rc == 0
    assert "Golden vectors: 3" in out
    assert "event_v1_001.bin" in out
    assert "source_ip" in out


def test_check_evidence_prints_index_summary():
    rc, out = _run("check_evidence.py")
    assert rc == 0
    assert "Evidence entries:" in out
    assert "Level summary:" in out
    assert "no provenance.json" in out


def test_read_vectors_finds_metadata():
    rc, out = _run("read_vectors.py")
    assert rc == 0
    assert "Exists: True" in out
    assert "Total vectors:" in out
