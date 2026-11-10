"""BLOCK-LABEL-038: candidate lists are labeled as local-only (behavioral).

No active writer maintains logs/blocked_ips.json or logs/quarantine.json
(the legacy direct-write path is gone), so entries are stale candidates:
neither presence (not proof of a live WFP filter) nor absence (not proof
of no filters) says anything about live state. block/quarantine list must
therefore label their provenance and point at enforce status instead of
printing bare `ip reason` lines that read as live blocks. E2.

S3-01: this file used to create and unlink `logs/blocked_ips.json` and
`logs/quarantine.json` inside the repository, which violates TEST HYGIENE
item 2 — a test that dirtied every subsequent `truth.py`/release run. The CLI
now honours `AEGIS_LOGS_DIR`, so the fixture state lives in `tmp_path` and the
tracked tree is asserted untouched around every test.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CLI = REPO / "tools" / "aegisctl.py"
TRACKED_LOG_FILES = (
    REPO / "logs" / "blocked_ips.json",
    REPO / "logs" / "quarantine.json",
)


def run(logs_dir: Path, *argv: str):
    env = dict(os.environ)
    env["AEGIS_LOGS_DIR"] = str(logs_dir)
    return subprocess.run(
        [sys.executable, str(CLI), *argv],
        capture_output=True, text=True, timeout=60, cwd=REPO, env=env,
    )


@pytest.fixture
def logs_dir(tmp_path: Path) -> Path:
    target = tmp_path / "logs"
    target.mkdir()
    return target


@pytest.fixture(autouse=True)
def tracked_tree_untouched():
    """S3-01 regression pin: these tests may never write repository logs/."""
    before = tuple(p.exists() for p in TRACKED_LOG_FILES)
    yield
    after = tuple(p.exists() for p in TRACKED_LOG_FILES)
    assert after == before, (
        "test wrote tracked-tree state under logs/ (TEST HYGIENE item 2): "
        f"{[(p.name, a) for p, a in zip(TRACKED_LOG_FILES, after)]}"
    )


def test_block_list_empty_names_provenance(logs_dir: Path):
    proc = run(logs_dir, "block", "list")
    assert proc.returncode == 0, proc.stderr
    assert "No IPs" in proc.stdout  # Gate-F compatibility
    assert "local candidates only" in proc.stdout
    assert "enforce status" in proc.stdout


def test_quarantine_list_empty_names_provenance(logs_dir: Path):
    proc = run(logs_dir, "quarantine", "list")
    assert proc.returncode == 0, proc.stderr
    assert "No IPs" in proc.stdout
    assert "local candidates only" in proc.stdout
    assert "enforce status" in proc.stdout


def test_block_list_entries_labeled_not_live(logs_dir: Path):
    (logs_dir / "blocked_ips.json").write_text(
        json.dumps({"blocked_ips": [{"ip": "203.0.113.7", "reason": "lab"}]}),
        encoding="utf-8",
    )
    proc = run(logs_dir, "block", "list")
    assert proc.returncode == 0, proc.stderr
    assert "203.0.113.7" in proc.stdout
    assert "not live filter state" in proc.stdout
    assert "BLOCKED" not in proc.stdout


def test_quarantine_list_entries_labeled_not_live(logs_dir: Path):
    (logs_dir / "quarantine.json").write_text(
        json.dumps({"quarantined_ips": [{"ip": "198.51.100.9", "reason": "lab"}]}),
        encoding="utf-8",
    )
    proc = run(logs_dir, "quarantine", "list")
    assert proc.returncode == 0, proc.stderr
    assert "198.51.100.9" in proc.stdout
    assert "not live state" in proc.stdout
