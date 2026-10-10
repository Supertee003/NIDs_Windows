"""EVT-165: receipt-aware threat graph pins (no tree writes).

edge_style is pure (claim-labeled colors, never raises); select_log
follows the newest-wins rule on tmp fixtures; the HTML build runs on a
tmp feed (reports/ stays untouched by tests) and is skipped only when
networkx/pyvis are absent.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from tools.aegisctl.graph import (
    COLOR_CONFIRMED,
    COLOR_DEFAULT,
    COLOR_OBSERVED,
    COLOR_UNVERIFIED,
    build_threat_graph,
    edge_style,
    read_records,
    select_log,
)

ENFORCED_LINE = {
    "ts_ms": 1791296893400, "level": "critical", "event": "signature_match",
    "rule": "4237725842", "src_ip": "192.168.1.100", "policy": "block",
    "decision": "block", "enforcement_status": "enforced",
    "host_effect_confirmed": True, "provider": "wfp",
    "filter_id": 301, "request_id": 302,
}

OBSERVED_LINE = {
    "ts_ms": 1791296893401, "level": "warn", "event": "signature_match",
    "rule": "1", "src_ip": "10.0.0.1", "policy": "alert",
    "decision": "alert", "enforcement_status": "observed",
    "host_effect_confirmed": False, "filter_id": 0, "request_id": 0,
}


def test_edge_colors_follow_receipt_evidence():
    color, label, dashed = edge_style(dict(ENFORCED_LINE))
    assert color == COLOR_CONFIRMED and dashed is False
    assert "receipt" in label
    color, label, dashed = edge_style(dict(OBSERVED_LINE))
    assert color == COLOR_OBSERVED and dashed is False
    lying = dict(ENFORCED_LINE, host_effect_confirmed=False,
                 filter_id=0, request_id=0, provider="")
    color, label, dashed = edge_style(lying)
    assert color == COLOR_UNVERIFIED and dashed is True
    assert "NO receipt" in label
    assert edge_style({})[0] == COLOR_DEFAULT
    assert edge_style(None)[0] == COLOR_DEFAULT


def test_select_log_prefers_newest(tmp_path):
    old = tmp_path / "old.ndjson"
    new = tmp_path / "new.ndjson"
    old.write_text("{}\n", encoding="utf-8")
    new.write_text("{}\n", encoding="utf-8")
    import os
    import time
    now = time.time()
    os.utime(old, (now - 100, now - 100))
    os.utime(new, (now, now))
    assert select_log([old, new]) == new
    assert select_log([new, old]) == new
    assert select_log([tmp_path / "missing.ndjson"]) == tmp_path / "missing.ndjson"


def test_read_records_respects_limit_and_skips_garbage(tmp_path):
    feed = tmp_path / "feed.ndjson"
    lines = ["not json", json.dumps(ENFORCED_LINE), "", json.dumps(OBSERVED_LINE)]
    feed.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert len(read_records(feed, limit=0)) == 2
    assert len(read_records(feed, limit=1)) == 1
    assert read_records(tmp_path / "nope.ndjson") == []


def test_build_renders_receipt_colors(tmp_path):
    pytest.importorskip("pyvis")
    pytest.importorskip("networkx")
    out = tmp_path / "threat_graph.html"
    parsed, nodes, edges = build_threat_graph(
        [dict(ENFORCED_LINE), dict(OBSERVED_LINE)], out, limit=500)
    # 2 records, distinct src+rule each: 2 src + 2 rule + hub = 5 nodes,
    # 2 edges per record = 4.
    assert (parsed, nodes, edges) == (2, 5, 4)
    html = out.read_text(encoding="utf-8")
    assert COLOR_CONFIRMED in html and COLOR_OBSERVED in html
