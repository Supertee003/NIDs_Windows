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
