"""EVT-175: attack-visibility demo pins (no unmarked traffic, ever).

The demo fires exactly one marked canary (AEGIS_FIXTURE + TEST rule
ids, same sanctioned pattern as gate-E). Pins:
  - every fixture carries the marker (static: no one can silently add
    an unmarked live-fire payload);
  - --dry-run exits 0 and fires nothing (no system touch);
  - graph --json emits machine-readable result (chainable output).
The live end-to-end run happens once per change, by hand, and its
output is recorded in the EVT -- never in the suite (a suite must not
write forensic evidence, even marked).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def test_fixtures_all_carry_the_marker():
    text = (REPO / "scripts" / "aegis_event_gen.py").read_text(encoding="utf-8")
    assert "AEGIS_FIXTURE" in text
    for name in ("xss", "path-traversal", "command-injection"):
        assert '"%s"' % name in text, name


def test_demo_dry_run_fires_nothing():
    proc = subprocess.run(
        [sys.executable, "scripts/attack_demo.py", "--dry-run"],
        cwd=str(REPO), capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    assert "dry run: nothing fired" in proc.stdout
    assert "1. fire:" in proc.stdout and "4. graph:" in proc.stdout


def test_graph_json_is_machine_readable(tmp_path):
    import json
    out = tmp_path / "g.json.html"
    proc = subprocess.run(
        [sys.executable, "tools/aegisctl.py", "graph", "--limit", "5",
         "--out", str(out), "--json"],
        cwd=str(REPO), capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    doc = json.loads(proc.stdout.strip().splitlines()[-1])
    assert doc["command"] == "graph"
    assert doc["parsed"] >= 0 and doc["nodes"] >= 1
    assert out.is_file()
