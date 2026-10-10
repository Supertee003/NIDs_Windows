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

# script -> pointers it must reference. ("cmd", x) must be a live aegisctl
# subcommand; ("file", rel) must exist in the repo. No silent deletions,
# no pointers to dead ends.
POINTERS = {
    "scripts/aegis_console.py": [("cmd", "console")],
    "scripts/aegis_console_pro.py": [("cmd", "console")],
    "scripts/aegis_graph.py": [("cmd", "graph")],
    "scripts/aegis_status.py": [("cmd", "components")],
    "scripts/aegis_api.py": [("cmd", "health"), ("cmd", "metrics"), ("cmd", "events")],
    "scripts/aegis_unblock.py": [("cmd", "block")],
    "scripts/Dashboard.py": [("cmd", "console")],
    "scripts/analyze_existing.py": [("file", "scripts/analyze_vectors.py")],
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
        for kind, token in wants:
            if kind == "cmd":
                assert ("aegisctl %s" % token) in header or \
                       ("aegisctl.py %s" % token) in header, (rel, token)
                assert token in subcommands, (rel, token)
            else:
                assert token in header, (rel, token)
                assert (REPO / token).is_file(), (rel, token)


def test_retired_bats_stay_retired():
    # EVT-167: blanket clean/kill bats contradict the service topology
    # (service kills orphan SCM, dist wipes fight the live brain).
    for rel in ("scripts/clean_aegis.bat", "scripts/build_all.bat"):
        text = (REPO / rel).read_text(encoding="utf-8", errors="replace")[:1500]
        assert "SUPERSEDED (EVT-167)" in text, rel
    stop = (REPO / "scripts" / "stop_aegis.bat").read_text(encoding="utf-8", errors="replace")
    assert "stop --all" in stop
    assert "taskkill /IM aegis_nids.exe" not in stop
    assert "taskkill /F /IM aegis_nids.exe" not in stop
