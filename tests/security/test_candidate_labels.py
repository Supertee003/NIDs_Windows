"""BLOCK-LABEL-038: candidate lists are labeled as local-only (behavioral).

No active writer maintains logs/blocked_ips.json or logs/quarantine.json
(the legacy direct-write path is gone), so entries are stale candidates:
neither presence (not proof of a live WFP filter) nor absence (not proof
of no filters) says anything about live state. block/quarantine list must
therefore label their provenance and point at enforce status instead of
printing bare `ip reason` lines that read as live blocks. E2.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CLI = REPO / "tools" / "aegisctl.py"
BLOCK_FILE = REPO / "logs" / "blocked_ips.json"
QUAR_FILE = REPO / "logs" / "quarantine.json"


def run(*argv: str):
    return subprocess.run(
        [sys.executable, str(CLI), *argv],
        capture_output=True, text=True, timeout=60, cwd=REPO,
    )


def cleanup():
    for p in (BLOCK_FILE, QUAR_FILE):
        p.unlink(missing_ok=True)


def setup_function(_):
    cleanup()


def teardown_function(_):
    cleanup()


def test_block_list_empty_names_provenance():
    proc = run("block", "list")
    assert proc.returncode == 0, proc.stderr
    assert "No IPs" in proc.stdout  # Gate-F compatibility
    assert "local candidates only" in proc.stdout
    assert "enforce status" in proc.stdout


def test_quarantine_list_empty_names_provenance():
    proc = run("quarantine", "list")
    assert proc.returncode == 0, proc.stderr
    assert "No IPs" in proc.stdout
    assert "local candidates only" in proc.stdout
    assert "enforce status" in proc.stdout


def test_block_list_entries_labeled_not_live():
    BLOCK_FILE.write_text(
        json.dumps({"blocked_ips": [{"ip": "203.0.113.7", "reason": "lab"}]}),
        encoding="utf-8",
    )
    try:
        proc = run("block", "list")
        assert proc.returncode == 0, proc.stderr
        assert "203.0.113.7" in proc.stdout
        assert "not live filter state" in proc.stdout
        assert "BLOCKED" not in proc.stdout
    finally:
        cleanup()


def test_quarantine_list_entries_labeled_not_live():
    QUAR_FILE.write_text(
        json.dumps({"quarantined_ips": [{"ip": "198.51.100.9", "reason": "lab"}]}),
        encoding="utf-8",
    )
    try:
        proc = run("quarantine", "list")
        assert proc.returncode == 0, proc.stderr
        assert "198.51.100.9" in proc.stdout
        assert "not live state" in proc.stdout
    finally:
        cleanup()
