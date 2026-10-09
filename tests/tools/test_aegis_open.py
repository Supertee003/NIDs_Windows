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
    # Terminal is now tracked by command line (no more stacking watch
    # windows); assert the shape of the live probe, not its state.
    assert isinstance(opener.display_running("terminal"), bool)


def test_display_running_returns_bool():
    # Live probes (loopback read-only); assert shape, not state.
    assert isinstance(opener.display_running("web"), bool)
    assert isinstance(opener.display_running("gui"), bool)
    assert isinstance(opener.display_running("tui"), bool)


def test_console_alive_probes_index_not_snapshot():
    # The old readiness probe hit /api/snapshot (~7s, dominated by
    # forensics.verify) with an 8s timeout, so a healthy console was
    # misread as dead and the launcher waited its full 60s and spawned
    # duplicates. The new probe reads the static index and must be fast.
    import socket
    import time
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]
    t0 = time.time()
    assert opener.console_alive(free_port, timeout_s=4.0) is False
    assert time.time() - t0 < 4.0
    # And it must probe the static index page, not a control-query endpoint.
    src = Path(__file__).resolve().parents[2] / "scripts" / "aegis_open.py"
    text = src.read_text(encoding="utf-8", errors="replace")
    assert 'urllib.request.urlopen("http://127.0.0.1:%d/" % port' in text


def test_port_owner_helpers_are_safe():
    # Read-only: an idle port has no owner, a bogus pid is not python.
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]
    assert opener._pids_on_tcp_port(free_port) == []
    assert opener._pid_is_python(2**31 - 1) is False
