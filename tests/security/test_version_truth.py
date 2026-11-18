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
    # EVT-179: the --version print site moved from main.go to
    # console_main.go in the console/service split. The pin follows the
    # print site and asserts it is the ONLY one, so the two entrypoints
    # can never report different versions (same rationale as the mouth
    # pin below).
    sites = []
    for name in ("main.go", "console_main.go", "service_main.go",
                 "server_runtime.go", "uuid_util.go"):
        src = (REPO / "go" / "aggregator" / name).read_text(encoding="utf-8")
        for m in re.finditer(r'Println\("aegis-aggregator ([^"]+)"\)', src):
            sites.append((name, m.group(1)))
    assert sites, "aggregator --version string not found"
    assert len(sites) == 1, f"competing version print sites: {sites}"
    assert cli_table()["aggregator"] == sites[0][1]


def test_daemon_version_handler_matches_contract():
    src = (REPO / "src" / "control" / "handler_registry.zig").read_text(encoding="utf-8")
    m = re.search(r'fn version\(.*?return (?:a\.dupe\(u8, )?"((?:[^"\\]|\\.)*)"', src, re.DOTALL)
    assert m, "daemon version handler payload not found"
    payload = json.loads(m.group(1).encode().decode("unicode_escape"))
    for key in ("core", "nose", "pep", "brain"):
        assert payload[key] == EXPECTED[key], (key, payload[key])


def test_mouth_binary_version_matches_cargo():
    # Mouth drift (Cargo 3.0.0 vs printed 1.0.0): the file header, the v3.0
    # redesign notes, and Cargo agree on 3.0.0 — the two print sites were
    # stale. Pin --version output and health JSON against Cargo so they
    # cannot drift apart again (verified against a real rustc build).
    cargo = (REPO / "mouth" / "Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.MULTILINE)
    assert m, "mouth Cargo version not found"
    want = m.group(1)
    src = (REPO / "mouth" / "windows_sec_monitor.rs").read_text(encoding="utf-8")
    assert f'println!("aegis-mouth {want}");' in src
    assert f'\\"version\\":\\"{want}\\"' in src


def test_toolchain_strings_match_release_record():
    # VER-BUILD-054: the in-binary build stamps must equal the toolchain
    # version recorded for releases (CI ZIG_VERSION 0.13.0). A bare
    # "zig-0.13" stamp sends operators to the wrong toolchain on rebuilds.
    rel = (REPO / "tools" / "release_engineering.py").read_text(encoding="utf-8")
    m = re.search(r'"zig":\s*"([^"]+)"', rel)
    assert m, "release toolchain record not found"
    want = f"zig-{m.group(1)}"
    for path in ("src/core/bridge_init.zig", "src/control/state_machine.zig"):
        src = (REPO / path).read_text(encoding="utf-8")
        assert f'"{want}"' in src, f"{path} must stamp {want}"
    for path in ("src/core/bridge_init.zig", "src/control/state_machine.zig"):
        src = (REPO / path).read_text(encoding="utf-8")
        assert not re.search(r'"zig-0\.13"(?!\.\d)', src), f"{path} still has short stamp"
