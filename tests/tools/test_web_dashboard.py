"""F5: web dashboard serves live data and degrades honestly.

Pins the F5-changed behavior of tools/aegisctl/web_dashboard/app.py:
  - _select_evidence_log picks the newest existing candidate (service
    path vs dev-tree path) and falls back to the last candidate.
    Uses tmp_path fixtures only; never touches the repo tree.
  - snapshot() carries the queue.stats key (additive; {} when the
    daemon predates the command) alongside the existing schema.
  - WEB-002: the kernel sensor view is additive and cost-separated --
    the snapshot carries sensor counters derived from queue.stats (never
    the ~4s forensic pages), /api/kernel serves the 60s-cached record
    pages, and both degrade honestly.
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


# --- WEB-002 kernel sensor view pins ---------------------------------------
# The view is additive and cost-separated: sensor counters derive from the
# queue.stats doc the snapshot already carries (zero extra control calls);
# record pages ride /api/kernel behind a 60s cache because each
# forensics.list page costs a retained-window scan + hash-chain verify
# (~4s). Nothing here is inferred: failures render as unavailable.

def _queue_doc():
    return {
        "depth": 7, "pushed_total": 100, "dropped_total": 4, "shed_overload": 1,
        "wfp": {"state": "ok", "reads": 10, "rows": 20, "last_bytes": 0},
        "minifilter": {"state": "ok", "reads": 11, "rows": 21, "last_bytes": 0, "dropped": 2},
        "by_source": [
            {"name": "capture_etw", "ordinal": 2, "pushed": 90, "dropped": 3},
            {"name": "capture_wfp", "ordinal": 21, "pushed": 20, "dropped": 1},
            {"name": "capture_fim", "ordinal": 3, "pushed": 30, "dropped": 2},
        ],
    }


def test_web002_kernel_sensors_extracted_from_queue_doc():
    sensors = app_module._kernel_sensors(_queue_doc())
    assert sensors["available"] is True
    assert sensors["wfp"]["rows"] == 20
    assert sensors["minifilter"]["dropped"] == 2
    assert [e["name"] for e in sensors["ingress"]] == ["capture_wfp", "capture_fim"]
    assert sensors["ingress"][0] == {"name": "capture_wfp", "pushed": 20, "dropped": 1}
    assert sensors["depth"] == 7 and sensors["dropped_total"] == 4


def test_web002_kernel_sensors_without_queue_doc_degrade():
    sensors = app_module._kernel_sensors(None)
    assert sensors["available"] is False
    assert sensors["wfp"] is None and sensors["minifilter"] is None
    assert sensors["ingress"] == []


def test_web002_kernel_feed_doc_normalizes_and_degrades():
    ok = app_module._kernel_feed_doc({
        "available": True, "records": [{"record_seq": 5}], "records_matched": 1,
        "records_returned": 1, "ring_records": 100, "oldest_record_seq": 50,
        "truncated": False, "verified": True, "integrity": "ok"})
    assert ok["available"] is True and ok["records"][0]["record_seq"] == 5
    assert ok["verified"] is True and ok["integrity"] == "ok"
    down = app_module._kernel_feed_doc(None)
    assert down["available"] is False and down["records"] == []
    assert down["integrity"] == "unavailable" and down["verified"] is False


def test_web002_kernel_feeds_query_both_sources_once(monkeypatch):
    calls = []

    def fake_read(command, payload=None):
        calls.append((command, dict(payload or {})))
        return {
            "available": True,
            "records": [{"record_seq": 42, "event_id": 7, "rule_id": 0,
                         "source": 1, "source_name": "wfp_sensor",
                         "source_space": "canonical", "payload_len": 42,
                         "verified": True}],
            "records_matched": 1, "records_returned": 1, "truncated": False,
            "next_after": None, "ring_records": 100, "oldest_record_seq": 9,
            "max_bytes": 65536, "integrity": "ok", "verified": True,
        }

    monkeypatch.setattr(app_module, "_read", fake_read)
    app_module._reset_snapshot_cache()
    try:
        doc = app_module._read_kernel_feeds_cached()
        forensic_calls = [c for c in calls if c[0] == "forensics.list"]
        assert sorted(c[1]["source"] for c in forensic_calls) == [1, 14]
        assert all(c[1]["limit"] == app_module._KERNEL_FEED_LIMIT for c in forensic_calls)
        assert all(c[1]["max_bytes"] == app_module._KERNEL_FEED_MAX_BYTES for c in forensic_calls)
        assert doc["feeds"]["wfp"]["records"][0]["record_seq"] == 42
        assert doc["feeds"]["file"]["available"] is True
        before = len(calls)
        app_module._read_kernel_feeds_cached()  # inside TTL: served from cache
        assert len(calls) == before
    finally:
        app_module._reset_snapshot_cache()


def test_web002_kernel_feeds_do_not_cache_pipe_failure(monkeypatch):
    calls = []

    def failing_read(command, payload=None):
        calls.append(command)
        return {}

    monkeypatch.setattr(app_module, "_read", failing_read)
    app_module._reset_snapshot_cache()
    try:
        doc = app_module._read_kernel_feeds_cached()
        assert doc["feeds"]["wfp"]["available"] is False
        assert doc["feeds"]["file"]["integrity"] == "unavailable"
        # A failed read must not pin an empty answer: the next call retries.
        app_module._read_kernel_feeds_cached()
        assert calls.count("forensics.list") == 4
    finally:
        app_module._reset_snapshot_cache()


def test_web002_snapshot_carries_kernel_sensors_without_forensic_feeds(monkeypatch):
    calls = []

    def fake_read(command, payload=None):
        calls.append(command)
        return _queue_doc() if command == "queue.stats" else {}

    monkeypatch.setattr(app_module, "_read", fake_read)
    app_module._reset_snapshot_cache()
    try:
        snap = app_module.snapshot()
        sensors = snap["kernel"]["sensors"]
        assert sensors["wfp"]["rows"] == 20
        assert [e["name"] for e in sensors["ingress"]] == ["capture_wfp", "capture_fim"]
        # The 3s/SSE snapshot path must never carry the ~4s forensic pages.
        assert "forensics.list" not in calls
    finally:
        app_module._reset_snapshot_cache()


def test_web002_api_kernel_endpoint_answers(monkeypatch):
    routes = {rule.rule for rule in app_module.app.url_map.iter_rules()}
    assert "/api/kernel" in routes

    def fake_read(command, payload=None):
        return _queue_doc() if command == "queue.stats" else {}

    monkeypatch.setattr(app_module, "_read", fake_read)
    app_module._reset_snapshot_cache()
    try:
        client = app_module.app.test_client()
        response = client.get("/api/kernel")
        assert response.status_code == 200
        body = response.get_json()
        assert body["schema"] == "aegis.kernel.v1"
        assert body["sensors"]["minifilter"]["dropped"] == 2
        assert set(body["feeds"]) == {"wfp", "file"}
        assert body["feeds"]["wfp"]["available"] is False  # failure labeled, not hidden
    finally:
        app_module._reset_snapshot_cache()


def test_web002_index_page_has_kernel_section():
    client = app_module.app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Kernel Sensors" in html
    assert "kernelSensors" in html and "kernelFeeds" in html
    assert "/api/kernel" in html
    assert 'href="#kernel"' in html
