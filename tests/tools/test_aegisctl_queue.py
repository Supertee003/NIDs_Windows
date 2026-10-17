"""G1: aegisctl queue display stays pure and honest.

Pins _format_queue_rows (the only new logic behind `aegisctl.py queue`):
  - bucket + stage rows render from the daemon response verbatim,
  - missing keys degrade to '?' instead of raising,
  - empty bucket/stage lists still print the summary line,
  - EVT-211: the wfp health row renders the provider state, and a missing
    provider is a LABELED absence, never a silent zero.

Read-only: imports the CLI module (import-guarded, no side effects),
writes nothing to the tree, contacts no daemon.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"


def _load_cli():
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    spec = importlib.util.spec_from_file_location(
        "aegisctl_queue_under_test", TOOLS_DIR / "aegisctl.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["aegisctl_queue_under_test"] = module
    spec.loader.exec_module(module)
    return module


cli = _load_cli()

SAMPLE = {
    "queue_size": 4096,
    "depth": 12,
    "pushed_total": 100,
    "dropped_total": 3,
    "by_source": [
        {"ordinal": 2, "name": "capture_etw", "pushed": 90, "dropped": 3},
        {"ordinal": 99, "name": "system", "pushed": 10, "dropped": 0},
    ],
    "pipeline": [
        {"stage": "capture_to_decode", "count": 100, "p50_ns": 1000,
         "p95_ns": 2000, "p99_ns": 3000, "mean_ns": 1500.0, "max_ns": 9000},
    ],
}


def test_format_queue_rows_renders_buckets_and_stages():
    rows = cli._format_queue_rows(SAMPLE)
    assert rows[0] == "queue 12/4096 pushed=100 dropped=3 shed_overload=?"
    assert rows[1] == "  src=capture_etw(2) pushed=90 dropped=3"
    assert rows[2] == "  src=system(99) pushed=10 dropped=0"
    assert "stage=capture_to_decode" in rows[3]
    assert "p50=1000ns" in rows[3]


def test_format_queue_rows_renders_etw_and_shed():
    response = dict(SAMPLE)
    response["shed_overload"] = 7
    response["etw"] = {
        "process_start": 5, "file_name_create": 50, "file_name_delete": 2,
        "file_write": 900, "reg_create": 1, "reg_set": 30, "dropped_unmapped": 4,
        "predecode_dropped": 8000, "shed_exempted": 11,
    }
    rows = cli._format_queue_rows(response)
    assert rows[0] == "queue 12/4096 pushed=100 dropped=3 shed_overload=7"
    assert rows[3] == "  etw start=5 name=50+2 write=900 reg=1+30 unmapped=4 predecode=8000 exempt=11"


def test_format_queue_rows_tolerates_missing_keys():
    rows = cli._format_queue_rows({})
    assert rows == ["queue ?/? pushed=? dropped=? shed_overload=?"]


def test_format_queue_rows_renders_wfp_health_row():
    response = dict(SAMPLE)
    response["wfp"] = {"state": "ok", "reads": 42, "rows": 7, "last_bytes": 256}
    rows = cli._format_queue_rows(response)
    # SAMPLE has no etw block, so wfp lands right after the source rows.
    assert "  wfp state=ok reads=42 rows=7 last_bytes=256" in rows


def test_format_queue_rows_labels_wfp_absence():
    # EVT-211: an absent provider must render as a LABELED state, never a
    # silent zero; 'unavailable' carries the explicit absence note.
    response = dict(SAMPLE)
    response["wfp"] = {"state": "unavailable", "reads": 0, "rows": 0, "last_bytes": 0}
    rows = cli._format_queue_rows(response)
    assert (
        "  wfp state=unavailable reads=0 rows=0 last_bytes=0 "
        "(kernel flow rows absent until provider returns)" in rows
    )


def test_format_queue_rows_labels_wfp_unknown():
    response = dict(SAMPLE)
    response["wfp"] = {"state": "unknown"}
    rows = cli._format_queue_rows(response)
    assert (
        "  wfp state=unknown reads=? rows=? last_bytes=? "
        "(telemetry loop has not reported)" in rows
    )


def test_format_queue_rows_omits_wfp_when_absent():
    # Daemons that predate the wfp block must not get an invented row.
    rows = cli._format_queue_rows(SAMPLE)
    assert not any("wfp" in row for row in rows)


def test_format_queue_rows_renders_minifilter_health_row():
    # EVT-230: the kernel minifilter health row, including the kernel ring's
    # own dropped counter (ring overflow is operator-visible, never silent).
    response = dict(SAMPLE)
    response["minifilter"] = {
        "state": "ok", "reads": 12, "rows": 3, "last_bytes": 1416, "dropped": 0,
    }
    rows = cli._format_queue_rows(response)
    assert "  minifilter state=ok reads=12 rows=3 last_bytes=1416 dropped=0" in rows


def test_format_queue_rows_labels_minifilter_absence():
    # EVT-230: a driver-absent host must render a LABELED state with the
    # explicit absence note, never a silent zero.
    response = dict(SAMPLE)
    response["minifilter"] = {
        "state": "unavailable", "reads": 0, "rows": 0, "last_bytes": 0, "dropped": 0,
    }
    rows = cli._format_queue_rows(response)
    assert (
        "  minifilter state=unavailable reads=0 rows=0 last_bytes=0 dropped=0 "
        "(kernel file/process rows absent until driver loads)" in rows
    )


def test_format_queue_rows_labels_minifilter_unknown():
    response = dict(SAMPLE)
    response["minifilter"] = {"state": "unknown"}
    rows = cli._format_queue_rows(response)
    assert (
        "  minifilter state=unknown reads=? rows=? last_bytes=? dropped=? "
        "(reader loop has not reported)" in rows
    )


def test_format_queue_rows_omits_minifilter_when_absent():
    # Daemons that predate the minifilter block must not get an invented row.
    rows = cli._format_queue_rows(SAMPLE)
    assert not any("minifilter" in row for row in rows)
