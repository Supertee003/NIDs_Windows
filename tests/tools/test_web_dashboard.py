"""F5: web dashboard serves live data and degrades honestly.

Pins the F5-changed behavior of tools/aegisctl/web_dashboard/app.py:
  - _select_evidence_log picks the newest existing candidate (service
    path vs dev-tree path) and falls back to the last candidate.
    Uses tmp_path fixtures only; never touches the repo tree.
  - snapshot() carries the queue.stats key (additive; {} when the
    daemon predates the command) alongside the existing schema.
  - the Flask app answers /api/snapshot with HTTP 200 even when the
    daemon is unreachable (graceful diagnostic mode), and binds
    localhost only (checked statically: no 0.0.0.0 bind).

The live-data proof (feed path = service log, queue buckets present)
runs against the deployed daemon, not here.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"


def _load_app():
    # app.py uses explicit relative imports (..api, ..contracts), so it
    # must load as its real dotted name under tools/ on sys.path.
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    import importlib

    module = importlib.import_module("aegisctl.web_dashboard.app")
    sys.modules["web_dashboard_under_test"] = module
    return module


app_module = _load_app()


def _touch(path: Path, mtime: float) -> Path:
    path.write_text("{}\n", encoding="utf-8")
    os.utime(path, (mtime, mtime))
    return path


def test_select_evidence_log_prefers_newest(tmp_path):
    old = _touch(tmp_path / "old.ndjson", 1000.0)
    new = _touch(tmp_path / "new.ndjson", 2000.0)
    assert app_module._select_evidence_log([old, new]) == new
    assert app_module._select_evidence_log([new, old]) == new
    assert app_module._select_evidence_log([tmp_path / "missing.ndjson", new]) == new
    fallback = tmp_path / "fallback.ndjson"
    assert app_module._select_evidence_log([fallback]) == fallback


def test_snapshot_schema_carries_queue_key():
    app_module._reset_snapshot_cache()  # live TTL cache; tests want fresh
    assert "queue" in app_module.snapshot()


def test_api_snapshot_answers_without_daemon():
    app_module._reset_snapshot_cache()  # live TTL cache; tests want fresh
    client = app_module.app.test_client()
    response = client.get("/api/snapshot")
    assert response.status_code == 200
    body = response.get_json()
    assert body["schema"] == "aegis.operator.snapshot.v1"
    assert "queue" in body


def test_no_wildcard_bind():
    source = (TOOLS_DIR / "aegisctl" / "web_dashboard" / "app.py").read_text(encoding="utf-8")
    assert 'host="127.0.0.1"' in source
    assert 'host="0.0.0.0"' not in source


def test_stream_emits_connected_frame_first():
    # SSE smoke: the first frame must be the connect preamble (no
    # snapshot required), so this stays fast and daemon-independent.
    stream = app_module._sse_events(interval_s=3600)
    first = next(stream)
    assert first.startswith(": connected")
    assert "retry:" in first
    stream.close()


def test_snapshot_carries_five_components():
    # EVT-162: every snapshot carries the concept registry (fast path:
    # health-derived + path checks, so no new mocks needed here).
    app_module._reset_snapshot_cache()  # live TTL cache; tests want fresh
    comps = app_module.snapshot()["components"]
    assert [c["id"] for c in comps] == ["core", "brain", "nose", "mouth", "bridge"]
    for comp in comps:
        for key in ("name", "language", "role", "version", "status"):
            assert comp[key], (comp["id"], key)
    assert [c["name"] for c in comps] == [
        "AEGIS Core", "AEGIS Brain", "AEGIS Nose", "AEGIS Mouth", "AEGIS Bridge"]


def test_index_page_has_components_section():
    # The section exists in the served template (JS renders the rows).
    client = app_module.app.test_client()
    html = client.get("/").get_data(as_text=True)
    assert "AEGIS Components" in html
    assert "compBody" in html


# --- WEB-001 (UI-001) integration pins ------------------------------------
# The four bullets the EVI entry WEB-001 listed as its pending integration
# test, pinned here: (1) the Flask app imports with the expected routes;
# (2) /api/status returns JSON carrying subsystem status; (3) / renders the
# dashboard HTML; (4) CLI + TUI + Web delegate to ONE control_api truth
# source (no duplicated business logic, no second wire):

def test_web001_flask_app_exposes_expected_routes():
    routes = {rule.rule for rule in app_module.app.url_map.iter_rules()}
    assert {"/", "/api/status", "/api/snapshot", "/api/incidents", "/health"} <= routes


def test_web001_api_status_returns_json_with_subsystem_status():
    app_module._reset_snapshot_cache()  # live TTL cache; tests want fresh
    client = app_module.app.test_client()
    response = client.get("/api/status")
    assert response.status_code == 200
    assert response.is_json
    body = response.get_json()
    assert body["schema"] == "aegis.operator.snapshot.v1"
    health = body["health"]
    assert isinstance(health, dict) and health.get("state")
    subsystems = health.get("subsystems")
    assert isinstance(subsystems, dict)  # never invented; empty is honest
    for name, sub in subsystems.items():
        assert isinstance(sub, dict) and sub.get("state"), name


def test_web001_index_renders_dashboard_html():
    client = app_module.app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert response.mimetype == "text/html"
    html = response.get_data(as_text=True)
    assert html.lstrip()[:15].lower().startswith("<!doctype html>")
    assert "AEGIS NIDS" in html
    assert "Operator Console" in html
    assert "/api/snapshot" in html  # the page polls the same JSON endpoint


def test_web001_cli_tui_web_share_one_control_api_truth_source():
    import importlib
    import importlib.util

    control_api = importlib.import_module("aegisctl.api.control_api")

    # WEB: identity, not a re-implementation.
    assert app_module.get_health_payload is control_api.get_health_payload
    assert app_module.query_control is control_api.query_control
    assert app_module.load_rules is control_api.load_rules

    # TUI (console.py): the same functions from the same module.
    tui = importlib.import_module("aegisctl.console")
    assert tui.get_all_status is control_api.get_all_status
    assert tui.load_rules is control_api.load_rules

    # CLI (tools/aegisctl.py): same module identity; business logic delegated.
    spec = importlib.util.spec_from_file_location(
        "aegisctl_cli_under_test", TOOLS_DIR / "aegisctl.py")
    cli = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(cli)
    assert cli.CONTROL_API_AVAILABLE is True
    assert cli.get_health_payload is control_api.get_health_payload
    assert cli.query_control is control_api.query_control

    # No UI owns a second wire: the control-pipe name appears only in
    # control_api (single definition point for the pipe endpoint).
    for rel in ("aegisctl.py", "aegisctl/console.py", "aegisctl/web_dashboard/app.py"):
        src = (TOOLS_DIR / rel).read_text(encoding="utf-8")
        assert "aegis_control" not in src, rel
