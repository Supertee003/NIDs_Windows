"""B2-HOTRL-034: Tier-2 hot-reload never kills the loop on a bad file.

The main loop re-reads Rules.json on mtime change. A concurrent save can
leave a torn (partial-JSON) file, and previously the bare read/compile in
the loop would raise out of `main` and kill Tier-2 detection entirely.
maybe_reload_rules() keeps the old engine on any load failure and reports
a reason; only a fully valid file swaps the engine. E2 (real files).
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from brain.windows_brain import (  # noqa: E402
    compile_tier2_rules,
    load_rules_from,
    maybe_reload_rules,
)


@pytest.fixture
def scratch() -> Path:
    """Function-scoped temp dir (manual TemporaryDirectory).

    Equivalent to tmp_path, used because this host's Temp holds an
    admin-owned dead `pytest-current` symlink that makes pytest's own
    tmp_path teardown raise PermissionError for ANY tmp_path test
    (proven with a trivial probe; unrelated to the code under test and
    unfixable from an unelevated shell). Same rule honored: nothing is
    written to the tracked tree or producer-owned paths.
    """
    name = tempfile.mkdtemp(prefix="aegis-hotrl-")
    yield Path(name)
    shutil.rmtree(name, ignore_errors=True)

GOOD_RULES = {
    "nids_rules": [
        {"rule_id": "R0056", "name": "sqli", "match_pattern": "' OR 1=1",
         "severity": "Critical", "action": "Drop"},
    ]
}


def write(path: Path, text: str, mtime: float):
    path.write_text(text, encoding="utf-8")
    os.utime(path, (mtime, mtime))


def test_unchanged_mtime_is_noop(scratch):
    target = scratch / "Rules.json"
    write(target, json.dumps(GOOD_RULES), 1_000_000)
    engine = compile_tier2_rules(GOOD_RULES)
    out = maybe_reload_rules(str(target), 1_000_000, GOOD_RULES, engine)
    assert out[3] is False and out[4] == "unchanged"
    assert out[1] is engine  # identical object, not recompiled


def test_missing_file_keeps_engine(scratch):
    engine = compile_tier2_rules(GOOD_RULES)
    out = maybe_reload_rules(str(scratch / "absent.json"), 0, GOOD_RULES, engine)
    assert out[3] is False and out[4] == "stat_failed"
    assert out[1] is engine


def test_torn_json_keeps_engine(scratch, capsys):
    target = scratch / "Rules.json"
    write(target, '{"nids_rules": [{"rule_id": "R00', 2_000_000)
    engine = compile_tier2_rules(GOOD_RULES)
    out = maybe_reload_rules(str(target), 1_000_000, GOOD_RULES, engine)
    assert out[3] is False and out[4] == "load_failed"
    assert out[1] is engine
    assert "keeping previous engine" in capsys.readouterr().out


def test_empty_and_wrong_shape_keep_engine(scratch):
    engine = compile_tier2_rules(GOOD_RULES)
    target = scratch / "Rules.json"
    for bad in ("", "[]", "[1,2]", '{"rules": []}', "null"):
        write(target, bad, 3_000_000)
        out = maybe_reload_rules(str(target), 1_000_000, GOOD_RULES, engine)
        assert (out[3], out[1]) == (False, engine), bad
        assert out[4] == "load_failed", bad


def test_valid_change_swaps_engine(scratch):
    target = scratch / "Rules.json"
    write(target, json.dumps(GOOD_RULES), 1_000_000)
    engine = compile_tier2_rules(GOOD_RULES)
    updated = {"nids_rules": GOOD_RULES["nids_rules"] + [
        {"rule_id": "R9999", "name": "newrule", "match_pattern": "EVIL",
         "severity": "High", "action": "Alert"},
    ]}
    write(target, json.dumps(updated), 2_000_000)
    data, fresh, mtime, reloaded, reason = maybe_reload_rules(
        str(target), 1_000_000, GOOD_RULES, engine)
    assert (reloaded, reason) == (True, "reloaded")
    assert mtime == 2_000_000
    assert len(data["nids_rules"]) == 2
    assert fresh is not engine and "newrule" in fresh


def test_bad_regex_rule_does_not_kill_reload(scratch):
    target = scratch / "Rules.json"
    engine = compile_tier2_rules(GOOD_RULES)
    mixed = {"nids_rules": GOOD_RULES["nids_rules"] + [
        {"rule_id": "RBAD", "name": "badre", "regex_pattern": "([unclosed",
         "severity": "Low", "action": "Alert"},
    ]}
    write(target, json.dumps(mixed), 2_000_000)
    data, fresh, _, reloaded, _ = maybe_reload_rules(
        str(target), 1_000_000, GOOD_RULES, engine)
    assert reloaded is True  # per-rule guard in compile_tier2_rules holds
    assert "badre" not in fresh and "sqli" in fresh


def test_load_rules_from_rejects_non_object(scratch):
    target = scratch / "Rules.json"
    target.write_text("[1, 2]", encoding="utf-8")
    try:
        load_rules_from(str(target))
    except ValueError:
        pass
    else:
        raise AssertionError("non-object rules file must raise for startup fail-closed")
