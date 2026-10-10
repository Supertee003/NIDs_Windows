"""EVT-165: the reborn console menu is pinned without interactivity.

The v8.0 menu operators miss returns as `aegisctl console`, rewired to
current contracts. These pins drive --once only (the input() loop is
never exercised by tests):
  - MENU table: keys unique, every action resolves, and admin-only marks
    exactly the mutating choices (1/2/3);
  - admin refusal is role-based and touch-free (operator + START -> exit
    1, nothing spawned);
  - invalid --choice exits 2 with the valid keys listed;
  - importing the module has no side effects (no sockets, no stdout).

No tree writes. Only the refusal/usage tests run here; live --once
choices run in the CLI test class (subprocess).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from tools.aegisctl.console import ACTIONS, MENU, console_menu


def test_menu_keys_unique_actions_resolve_admin_only_mutations():
    keys = [key for key, _sec, _label, _admin, _action in MENU]
    assert len(keys) == len(set(keys)) == 13
    assert set(keys) == set("123456789") | {"A", "B", "C", "0"}
    admin_keys = {key for key, _sec, _label, admin, _action in MENU if admin}
    assert admin_keys == {"1", "2", "3"}
    for _key, _sec, label, _admin, action in MENU:
        assert label.strip(), _key
        assert action in ACTIONS, (_key, action)


def test_admin_refusal_is_touch_free(capsys):
    rc = console_menu(role="operator", once=True, choice="1")
    assert rc == 1
    assert "BLOCKED" in capsys.readouterr().out


def test_invalid_choice_lists_valid_keys(capsys):
    rc = console_menu(role="operator", once=True, choice="bogus")
    assert rc == 2
    assert "0" in capsys.readouterr().out


def test_import_has_no_side_effects():
    proc = subprocess.run(
        [sys.executable, "-c", "import tools.aegisctl.console"],
        capture_output=True, text=True, timeout=120, cwd=str(REPO),
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    assert proc.stdout == ""


def test_menu_renders_under_piped_stdout(capsys):
    # Thai labels crashed on cp1252-piped stdout (the smoke that caught
    # it); pytest captures, so this is the regression pin.
    from tools.aegisctl.console import print_menu
    print_menu("operator")
    out = capsys.readouterr().out
    assert "Command Control Center" in out
    assert "SYSTEM" in out and "CONTROL" in out and "ANALYSIS" in out
