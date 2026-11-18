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

import pytest


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
    # EVT-188: window probe is equally safe (bogus name -> no window).
    assert opener._pids_with_window("definitely-not-a-process-xyz-123") == []


def test_gui_skip_means_visible_window():
    # EVT-188: a lingering windowless egui process must not read as a
    # running display. The live GUI owns a visible window; assert the
    # probe agrees with the process list shape (list of ints, safe).
    pids = opener._pids_with_window("aegis_dashboard")
    assert isinstance(pids, list)
    assert all(isinstance(p, int) for p in pids)
    if opener._pids_by_name("aegis_dashboard"):
        assert isinstance(opener.display_running("gui"), bool)


def test_web_skip_opens_browser_unless_opted_out():
    # EVT-189: a running-but-invisible server is not a displayed surface.
    # The helper is the single browser-open call site for fresh starts and
    # SKIP alike; False is a pure no-op (suite-safe, no browser touched).
    assert opener._maybe_open_browser(False) is False
    src = Path(__file__).resolve().parents[2] / "scripts" / "aegis_open.py"
    text = src.read_text(encoding="utf-8", errors="replace")
    assert text.count("_maybe_open_browser(") >= 3  # def + fresh + SKIP


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


def test_keeper_plan_converges_only_the_dead():
    # Pure decision: alive members are never restarted, unknown counts as
    # dead (a watchdog that skips on "unknown" is how the 2h blind gap
    # happened). Order is service-first: nose/brain depend on the daemon.
    assert opener.keeper_plan(True, True, True) == []
    assert opener.keeper_plan(False, True, True) == ["service"]
    assert opener.keeper_plan(True, False, True) == ["nose"]
    assert opener.keeper_plan(True, True, False) == ["brain"]
    assert opener.keeper_plan(False, False, False) == ["service", "nose", "brain"]


def test_keeper_task_cmd_shape():
    # The scheduled-task command must converge core only (keep, never open
    # with displays), run every 5 minutes, and run as SYSTEM so an
    # unattended tick can sc-start the service.
    install = opener.keeper_task_cmd("install")
    assert install[:4] == ["schtasks", "/create", "/tn", "AegisKeeper"]
    assert "/tr" in install and install[install.index("/tr") + 1].endswith("keep")
    for token in ("/sc", "minute", "/mo", "5", "/ru", "SYSTEM", "/f"):
        assert token in install
    assert opener.keeper_task_cmd("uninstall") == ["schtasks", "/delete", "/tn", "AegisKeeper", "/f"]
    try:
        opener.keeper_task_cmd("bogus")
    except ValueError:
        pass
    else:
        raise AssertionError("bad keeper task action must raise, not build")


def _keep_args(**over):
    import types
    base = {"install_task": False, "uninstall_task": False, "json": False}
    base.update(over)
    return types.SimpleNamespace(**base)


def test_cmd_keep_noop_when_all_alive():
    # Live predicates mocked alive: one True row, exit 0, no starter runs.
    from unittest.mock import patch
    with patch.object(opener, "service_state", return_value="RUNNING"), \
         patch.object(opener, "process_running", return_value=True), \
         patch.object(opener, "udp_port_owned", return_value=True), \
         patch.object(opener, "start_service") as svc, \
         patch.object(opener, "start_nose") as nose, \
         patch.object(opener, "start_brain") as brain:
        assert opener.cmd_keep(_keep_args()) == 0
    svc.assert_not_called()
    nose.assert_not_called()
    brain.assert_not_called()


def test_cmd_keep_restarts_only_dead_nose():
    # Nose down at plan time, alive at re-verify: starter runs once and
    # the converge row is green.
    from unittest.mock import patch
    ok_row = opener.summarize("start nose", True, "mocked")
    with patch.object(opener, "service_state", return_value="RUNNING"), \
         patch.object(opener, "process_running", side_effect=[False, True]), \
         patch.object(opener, "udp_port_owned", return_value=True), \
         patch.object(opener, "start_nose", return_value=ok_row) as nose:
        assert opener.cmd_keep(_keep_args()) == 0
    nose.assert_called_once_with()


def test_keep_service_prefers_scm_recovery():
    # SCM failure actions get the first chance; sc start only fires when
    # the grace wait observes nothing (patched here: no real sleeping).
    from unittest.mock import patch
    with patch.object(opener, "service_state", return_value="UNKNOWN"), \
         patch.object(opener, "wait_for", return_value=True), \
         patch.object(opener, "start_service") as svc:
        row = opener.keep_service()
        assert row["ok"] is True and "SCM" in row["detail"]
    svc.assert_not_called()
    with patch.object(opener, "service_state", return_value="STOPPED"), \
         patch.object(opener, "wait_for", return_value=False), \
         patch.object(opener, "start_service",
                       return_value=opener.summarize("start service", True, "mocked")) as svc:
        row = opener.keep_service()
        assert row["ok"] is True
    svc.assert_called_once_with()


def test_tui_surface_is_mouth_identity():
    # EVT-151 decision: mouth stays as the "tui" display surface. Pin the
    # exact identity so a rename silently orphaning windows_sec_monitor
    # (or the stop matcher missing it) fails loudly. Pure, no system touch.
    assert opener._DISPLAY_MATCH["tui"] == ("exe", "windows_sec_monitor")
    assert opener.TUI_EXE.name == "windows_sec_monitor.exe"
    assert opener.TUI_EXE.parent.name == "release"


def test_pids_by_cmdline_never_matches_self():
    # EVT-161: the query once matched the asker's own python command line
    # (a probe running this module reported itself as the watch window).
    # The pytest process command line always contains "pytest", so this
    # pin is deterministic on any host with no other pytest running it.
    import os
    assert os.getpid() not in opener._pids_by_cmdline("pytest")


def test_pids_by_cmdline_covers_pythonw():
    # EVT-171: keeper-spawned brains run as pythonw.exe; a python.exe-only
    # WQL filter missed them (stop said "was not running" with :9999
    # owned). Pin the query shape (no system touch) ...
    from unittest.mock import patch
    seen = {}

    def fake_run(cmd, timeout=60):
        seen["cmd"] = " ".join(cmd)
        return (0, "", "")

    with patch.object(opener, "run", side_effect=fake_run):
        assert opener._pids_by_cmdline("windows_brain") == []
    assert "pythonw.exe" in seen["cmd"]
    assert "python.exe" in seen["cmd"]


@pytest.mark.host_live
def test_udp_port_owner_is_readable_cross_elevation():
    # ... but argv matching cannot see an ELEVATED brain from a plain
    # shell, so the socket owner is authoritative. Live and read-only:
    # the current brain holds :9999 and the helper must name it.
    assert opener._pids_on_udp_port(9999), "live brain port owner missing"


def test_stop_brain_displaces_python_port_owners():
    # stop_supervised adds python owners of :9999 even when argv shows
    # nothing (same rule as the web stale-port cleanup).
    from unittest.mock import patch
    killed_with = []

    def fake_kill(pids):
        killed_with.extend(pids)
        return (list(pids), [])

    with patch.object(opener, "_pids_by_cmdline", return_value=[]), \
         patch.object(opener, "_pids_on_udp_port", return_value=[1234]), \
         patch.object(opener, "_pid_is_python", return_value=True), \
         patch.object(opener, "_kill_pids", side_effect=fake_kill), \
         patch.object(opener, "_pids_by_name", return_value=["n"]):
        rows = opener.stop_supervised()
    assert killed_with.count(1234) >= 1
    assert any(r["check"] == "stop brain" for r in rows)


def test_keeper_task_runs_windowless():
    # EVT-164: python.exe under a console-less task parent allocates a
    # visible console per tick (the blank Administrator popup). The task
    # must use pythonw.exe (same interpreter, GUI subsystem, no console).
    cmd = opener.keeper_task_cmd("install")
    target = cmd[cmd.index("/tr") + 1]
    assert "keep" in target
    assert target.startswith('"') and "pythonw.exe" in target


def test_keeper_lock_blocks_overlaps_only():
    # Fresh lock by a live pid blocks; stale/malformed/missing do not.
    import os
    import time
    from unittest.mock import patch
    with patch.object(opener, "KEEPER_LOCK_FILE", opener.Path(r"C:\Temp\aegis_keep_testprobe.lock")):
        probe = opener.KEEPER_LOCK_FILE
        try:
            probe.write_text("bogus", encoding="utf-8")
            assert opener._keeper_lock_busy() is False
            probe.write_text("%d %f" % (os.getpid(), time.time()), encoding="utf-8")
            assert opener._keeper_lock_busy() is True
            probe.write_text("%d %f" % (os.getpid(), time.time() - 3600), encoding="utf-8")
            assert opener._keeper_lock_busy() is False
            probe.write_text("999999999 %f" % (time.time(),), encoding="utf-8")
            assert opener._keeper_lock_busy() is False  # dead owner: takeover
        finally:
            try:
                probe.unlink()
            except OSError:
                pass


def test_cmd_keep_skips_when_another_run_is_fresh():
    from unittest.mock import patch
    with patch.object(opener, "_keeper_lock_busy", return_value=True), \
         patch.object(opener, "start_service") as svc, \
         patch.object(opener, "start_nose") as nose, \
         patch.object(opener, "start_brain") as brain:
        assert opener.cmd_keep(_keep_args()) == 2
    svc.assert_not_called()
    nose.assert_not_called()
    brain.assert_not_called()


def test_main_logs_and_returns_1_on_crash():
    # Under pythonw there is no console for the traceback: main() must
    # log it and return 1, never propagate.
    from unittest.mock import patch

    def _boom(args):
        raise RuntimeError("boom-marker-164")

    with patch.object(opener, "cmd_keep", side_effect=_boom):
        assert opener.main(["keep"]) == 1
