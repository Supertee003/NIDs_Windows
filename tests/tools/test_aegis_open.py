"""System opener: pure-helper pins (no system touch).

status/open/close themselves are proven live against the deployed
system (EVT); these pins cover the decision helpers only:
  - resolve_nose_iface: explicit interface wins, blank/absent falls
    back to auto-select (empty argv, never a broken flag value).
  - summarize/overall_exit/render: row truth table (True/False/None
    skipped) and exit-code mapping.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_opener():
    path = Path(__file__).resolve().parents[2] / "scripts" / "aegis_open.py"
    spec = importlib.util.spec_from_file_location("aegis_open_under_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["aegis_open_under_test"] = module
    spec.loader.exec_module(module)
    return module


opener = _load_opener()


def test_resolve_nose_iface_explicit_wins():
    cmd = opener.resolve_nose_iface({"AEGIS_NOSE_IFACE": r"\Device\NPF_X"})
    assert cmd == ["-iface", r"\Device\NPF_X"]
    legacy = opener.resolve_nose_iface({"AEGIS_CAPTURE_IFACE": r"\Device\NPF_Y"})
    assert legacy == ["-iface", r"\Device\NPF_Y"]


def test_resolve_nose_iface_blank_or_absent_means_auto():
    assert opener.resolve_nose_iface({}) == []
    assert opener.resolve_nose_iface({"AEGIS_NOSE_IFACE": "   "}) == []


def test_overall_exit_truth_table():
    ok = [opener.summarize("a", True), opener.summarize("b", True)]
    assert opener.overall_exit(ok) == 0
    bad = ok + [opener.summarize("c", False, "boom")]
    assert opener.overall_exit(bad) == 1
    skipped = [opener.summarize("d", None, "skipped")]
    assert opener.overall_exit(skipped) == 2
    mixed = [opener.summarize("e", True), opener.summarize("f", None)]
    assert opener.overall_exit(mixed) == 2


def test_render_marks_rows():
    rows = [opener.summarize("a", True), opener.summarize("b", False, "why"), opener.summarize("c", None)]
    text = opener.render(rows, as_json=False)
    assert "[OK  ] a" in text
    assert "[FAIL] b - why" in text
    assert "[SKIP] c" in text
    import json
    doc = json.loads(opener.render(rows, as_json=True))
    assert [r["ok"] for r in doc["rows"]] == [True, False, None]


def test_process_queries_are_safe():
    # Read-only probes: unknown names yield empty, killing nothing is a no-op.
    assert opener._pids_by_name("definitely-not-a-process-xyz-123") == []
    assert opener.process_running("definitely-not-a-process-xyz-123") is False
    assert opener._kill_pids([]) == ([], [])


def test_display_match_table_is_known_surfaces_only():
    assert set(opener._DISPLAY_MATCH) == {"web", "gui", "tui", "terminal"}
    assert opener.stop_display("bogus-surface")["ok"] is False
    assert opener.start_display("bogus-surface")["ok"] is False
    # Terminal windows are never tracked: always a fresh start decision.
    assert opener.display_running("terminal") is False


def test_display_running_returns_bool():
    # Live probe (loopback read-only); assert shape, not state.
    assert isinstance(opener.display_running("web"), bool)
