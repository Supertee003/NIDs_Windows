"""EVT-165: legacy headers must point at real commands (or none).

The old surfaces were retired with DEPRECATED pointers, several of them
false (a viewer offered where control died). Every SUPERSEDED pointer
below must name a subcommand that `aegisctl --help` actually lists, and
no legacy file may be deleted silently (presence pinned).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# script -> subcommands its header must reference (all must exist).
POINTERS = {
    "scripts/aegis_console.py": ["console"],
    "scripts/aegis_console_pro.py": ["console"],
    "scripts/aegis_graph.py": ["graph"],
    "scripts/aegis_status.py": ["components"],
    "scripts/aegis_api.py": ["health", "metrics", "events"],
    "scripts/aegis_unblock.py": ["block"],
}


def _subcommands() -> set:
    proc = subprocess.run(
        [sys.executable, "tools/aegisctl.py", "--help"],
        cwd=str(REPO), capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    matches = re.findall(r"\{([a-z,]+)\}", proc.stdout)
    assert matches, "usage line must enumerate subcommands"
    longest = max(matches, key=len)
    return set(longest.split(","))


def test_legacy_files_still_present():
    for rel in POINTERS:
        assert (REPO / rel).is_file(), rel


def test_headers_point_at_real_commands():
    subcommands = _subcommands()
    for rel, wants in POINTERS.items():
        header = (REPO / rel).read_text(encoding="utf-8", errors="replace")[:1200]
        assert "SUPERSEDED" in header, rel
        for token in wants:
            assert ("aegisctl %s" % token) in header or \
                   ("aegisctl.py %s" % token) in header, (rel, token)
            assert token in subcommands, (rel, token)
