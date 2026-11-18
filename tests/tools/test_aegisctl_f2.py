"""F2: events source selection, simulate bridge args, dashboard loop bounds.

Pins the pure helpers behind the F2 slice:
  - _select_event_log picks the newest existing candidate (service path
    vs dev-tree path) and yields None when neither exists. Uses tmp_path
    fixtures only; never touches the repo tree.

Read-only: imports the CLI module (import-guarded, no side effects),
writes nothing, contacts no daemon.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"


def _load_cli():
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    spec = importlib.util.spec_from_file_location(
        "aegisctl_f2_under_test", TOOLS_DIR / "aegisctl.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["aegisctl_f2_under_test"] = module
    spec.loader.exec_module(module)
    return module


cli = _load_cli()


def _touch(path: Path, mtime: float) -> Path:
    path.write_text("{}\n", encoding="utf-8")
    os.utime(path, (mtime, mtime))
    return path


def test_select_event_log_prefers_newest(tmp_path):
    old = _touch(tmp_path / "old.ndjson", 1000.0)
    new = _touch(tmp_path / "new.ndjson", 2000.0)
    assert cli._select_event_log([old, new]) == new
    assert cli._select_event_log([new, old]) == new


def test_select_event_log_skips_missing(tmp_path):
    live = _touch(tmp_path / "live.ndjson", 1500.0)
    assert cli._select_event_log([tmp_path / "nope.ndjson", live]) == live
    assert cli._select_event_log([tmp_path / "nope.ndjson"]) is None
    assert cli._select_event_log([]) is None
