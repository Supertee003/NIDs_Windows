"""BE-DIS-089: the daemon engine and the CLI read the same disabled file.

Failure mode this pins: `policy list` showed DISABLED from one path
while the detection engine loaded another (or none), so a rule shown
DISABLED still fired during an attack test. Contract:

  AC1. The canonical disabled path is configs/disabled_rules.json
       (colocated with the rule authority), for the CLI constant,
       the CLI list command, and the Zig engine.
  AC2. No disabled-rules reader targets the legacy singular config/ dir.
  AC3. The live file stays untracked (operator state, like
       policy_trust.json / cluster.json).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _slug(path: Path) -> str:
    return str(path).replace("\\", "/")


def test_cli_constant_points_at_the_canonical_file():
    from tools.aegisctl import config as aegisctl_config

    assert _slug(aegisctl_config.DISABLED_RULES_FILE).endswith(
        "/configs/disabled_rules.json"
    )


def test_cli_list_reads_the_canonical_file():
    source = (REPO_ROOT / "tools" / "aegisctl.py").read_text(encoding="utf-8")
    assert 'TOOLS_DIR.parent / "configs" / "disabled_rules.json"' in source


def test_no_disabled_reader_targets_the_legacy_singular_dir():
    for rel in (
        "tools/aegisctl.py",
        "tools/aegisctl/config.py",
        "tools/aegisctl/utils.py",
    ):
        source = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert '"config" / "disabled_rules.json"' not in source, rel
        assert "'config' / 'disabled_rules.json'" not in source, rel


def test_zig_engine_reads_the_canonical_file():
    source = (REPO_ROOT / "src" / "pipeline" / "rule_loader.zig").read_text(
        encoding="utf-8"
    )
    assert '"disabled_rules.json"' in source
    # The engine resolves through runtime_paths.configPath (configs/);
    # it must not join the singular legacy dir for this file.
    assert '"config" ++ ' not in source.replace("configs", "")


def test_live_disabled_file_stays_untracked():
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "configs/disabled_rules.json" in gitignore
    tracked = subprocess.run(
        ["git", "ls-files", "configs/disabled_rules.json", "config/disabled_rules.json"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert tracked.stdout.strip() == "", "live disabled file must not be tracked"


def test_policy_list_reports_daemon_authority():
    result = subprocess.run(
        [sys.executable, "tools/aegisctl.py", "policy", "list"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0
    assert "Active daemon rules:" in result.stdout
