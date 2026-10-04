"""VER-TRUTH-032: version surfaces mirror each component's own truth.

`aegisctl version` (CLI table) and the daemon `version` handler both
hardcoded versions that contradicted the components themselves (CLI said
nose 2.1.0 / brain 1.0.0 / aggregator 1.0.0; sources say 5.0.0 / 2.0.0 /
0.1.0). This pins the corrected table AND cross-checks it against the
authoritative sources, so the two surfaces cannot drift apart again
without a test failing. No daemon needed. E2.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CLI = REPO / "tools" / "aegisctl.py"

EXPECTED = {
    "core": "5.0.0",
    "nose": "5.0.0",
    "pep": "5.0.0",
    "brain": "2.0.0",
    "shield": "0.1.0",
    "bridge": "1.0.0",
    "aggregator": "0.1.0",
}


def run(*argv: str):
    return subprocess.run(
        [sys.executable, str(CLI), *argv],
        capture_output=True, text=True, timeout=60, cwd=REPO,
    )


def cli_table() -> dict:
    proc = run("version")
    assert proc.returncode == 0, proc.stderr
    rows = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in EXPECTED:
            rows[parts[0]] = parts[1]
    return rows


def test_cli_version_table_matches_contract():
    assert cli_table() == EXPECTED


def test_cli_nose_matches_nose_source():
    src = (REPO / "nose" / "main.go").read_text(encoding="utf-8")
    m = re.search(r'AEGIS_NOSE_VERSION\s*=\s*"([^"]+)"', src)
    assert m, "nose version constant not found"
    assert cli_table()["nose"] == m.group(1)


def test_cli_pep_matches_cargo_package():
    with open(REPO / "Cargo.toml", "rb") as fh:
        cargo = tomllib.load(fh)
    assert cli_table()["pep"] == cargo["package"]["version"]


def test_cli_brain_matches_brain_banner():
    src = (REPO / "brain" / "windows_brain.py").read_text(encoding="utf-8")
    m = re.search(r"AEGIS BRAIN (\d+\.\d+\.\d+)", src)
    assert m, "brain version banner not found"
    assert cli_table()["brain"] == m.group(1)


def test_cli_aggregator_matches_binary_version():
    src = (REPO / "go" / "aggregator" / "main.go").read_text(encoding="utf-8")
    m = re.search(r'Println\("aegis-aggregator ([^"]+)"\)', src)
    assert m, "aggregator --version string not found"
    assert cli_table()["aggregator"] == m.group(1)


def test_daemon_version_handler_matches_contract():
    src = (REPO / "src" / "control" / "handler_registry.zig").read_text(encoding="utf-8")
    m = re.search(r'fn version\(.*?return "((?:[^"\\]|\\.)*)"', src, re.DOTALL)
    assert m, "daemon version handler payload not found"
    payload = json.loads(m.group(1).encode().decode("unicode_escape"))
    for key in ("core", "nose", "pep", "brain"):
        assert payload[key] == EXPECTED[key], (key, payload[key])
