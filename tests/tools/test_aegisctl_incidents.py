"""EVT-210: `aegisctl.py incidents list` shows per-incident detail honestly.

Pins the display contract added with the daemon-side incident snapshot:
  - When the daemon returns an `incidents` array, rows render (highest
    score first, as the daemon orders them) and JSON passes them through.
  - When the daemon predates the view (no array), the text view ADMITS it
    ("detail unavailable") instead of printing a silent zero; JSON always
    carries an `incidents` list (empty when absent) so consumers can parse
    one shape.
  - Quiet (open == 0, empty array) prints "No open incidents.".

Read-only: imports the CLI module by path (guarded, no side effects),
stubs the control query in-process, writes nothing to the tree, contacts
no daemon. The Zig wiring is pinned by a source scan, not by running it.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "tools"
HANDLER = REPO_ROOT / "src" / "control" / "handler_registry.zig"
TRACKER = REPO_ROOT / "src" / "detection" / "threat_tracker.zig"
DAEMON = REPO_ROOT / "src" / "daemon.zig"


def _load_cli():
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    spec = importlib.util.spec_from_file_location(
        "aegisctl_incidents_under_test", TOOLS_DIR / "aegisctl.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["aegisctl_incidents_under_test"] = module
    spec.loader.exec_module(module)
    return module


cli = _load_cli()


def _args(**kwargs):
    base = {"json": False, "incidents_command": "list"}
    base.update(kwargs)
    return types.SimpleNamespace(**base)


def _run_with_response(monkeypatch, response):
    monkeypatch.setattr(cli, "CONTROL_API_AVAILABLE", True)
    monkeypatch.setattr(cli, "query_control", lambda *a, **k: response)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli.cmd_incidents(_args())
    return rc, buf.getvalue()


def _run_json_with_response(monkeypatch, response):
    monkeypatch.setattr(cli, "CONTROL_API_AVAILABLE", True)
    monkeypatch.setattr(cli, "query_control", lambda *a, **k: response)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli.cmd_incidents(_args(json=True))
    return rc, buf.getvalue()


def test_detail_rows_render_when_daemon_supplies_them(monkeypatch):
    response = {
        "incidents_total": 9, "incidents_open": 2, "detections": 100,
        "policies_matched": 80, "correlations": 0,
        "incidents": [
            {"id": 7, "flow_id": 3, "src_ip": "192.168.126.10",
             "severity": "alert", "state": "open", "score": 420,
             "evidence": 3},
            {"id": 5, "flow_id": 2, "src_ip": "192.168.126.20",
             "severity": "warning", "state": "open", "score": 130,
             "evidence": 2},
        ],
        "incidents_returned": 2, "incident_view_cap": 64,
    }
    rc, out = _run_with_response(monkeypatch, response)
    assert rc == 0
    assert "OPEN INCIDENTS" in out
    assert "id=7" in out and "192.168.126.10" in out and "score=420" in out
    assert "id=5" in out


def test_absent_array_is_admitted_not_a_silent_zero(monkeypatch):
    response = {
        "incidents_total": 9, "incidents_open": 5, "detections": 1,
        "policies_matched": 1, "correlations": 0,
    }
    rc, out = _run_with_response(monkeypatch, response)
    assert rc == 0
    assert "detail unavailable" in out
    assert "OPEN INCIDENTS" not in out


def test_quiet_host_prints_no_incidents(monkeypatch):
    response = {
        "incidents_total": 0, "incidents_open": 0, "detections": 0,
        "policies_matched": 0, "correlations": 0,
        "incidents": [], "incidents_returned": 0, "incident_view_cap": 64,
    }
    rc, out = _run_with_response(monkeypatch, response)
    assert rc == 0
    assert "No open incidents." in out


def test_json_always_carries_an_incidents_list(monkeypatch):
    absent = {
        "incidents_total": 0, "incidents_open": 0, "detections": 0,
        "policies_matched": 0, "correlations": 0,
    }
    rc, out = _run_json_with_response(monkeypatch, absent)
    assert rc == 0
    doc = json.loads(out)
    assert doc["incidents"] == []
    assert doc["available"] is True

    present = dict(absent)
    present["incidents"] = [{"id": 1, "score": 100}]
    present["incidents_returned"] = 1
    present["incident_view_cap"] = 64
    rc, out = _run_json_with_response(monkeypatch, present)
    doc = json.loads(out)
    assert doc["incidents"][0]["id"] == 1
    assert doc["incident_view_cap"] == 64


def test_zig_wiring_pins_snapshot_and_publication():
    # The daemon publishes its live tracker; the handler copies a bounded
    # snapshot; the source ordinal for WFP rows is its own bucket.
    handler = HANDLER.read_text(encoding="utf-8")
    tracker = TRACKER.read_text(encoding="utf-8")
    daemon = DAEMON.read_text(encoding="utf-8")
    assert "snapshotOpenIncidents" in handler
    assert "incident_view_cap" in handler
    assert "pub fn snapshotOpenIncidents" in tracker
    assert "g_live = &tt" in daemon
