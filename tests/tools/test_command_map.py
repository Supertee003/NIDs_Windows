"""EVT-170: the command map must cover every subcommand.

The deep analysis found naming confusion, not redundancy -- but a map
that silently drops new commands recreates the confusion. Pins:
  - every aegisctl subcommand appears in docs/OPERATOR_COMMAND_MAP.md;
  - the epilog role lines render in --help (the map is discoverable).
Read-only, no tree writes.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MAP = REPO / "docs" / "OPERATOR_COMMAND_MAP.md"


def _subcommands() -> set:
    proc = subprocess.run(
        [sys.executable, "tools/aegisctl.py", "--help"],
        cwd=str(REPO), capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    matches = re.findall(r"\{([a-z,]+)\}", proc.stdout)
    return set(max(matches, key=len).split(","))


def test_map_covers_every_subcommand():
    text = MAP.read_text(encoding="utf-8")
    missing = [name for name in sorted(_subcommands()) if name not in text]
    assert not missing, missing


def test_epilog_advertises_roles():
    proc = subprocess.run(
        [sys.executable, "tools/aegisctl.py", "--help"],
        cwd=str(REPO), capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0
    for token in ("roles", "daily", "incident", "maintain", "lab/dev",
                  "OPERATOR_COMMAND_MAP.md"):
        assert token in proc.stdout, token
