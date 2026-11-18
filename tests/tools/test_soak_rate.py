"""#29 measurement gate: soak_rate must fail closed on its own defects.

The window-003 tool reported `zero_drops: true, drops_total: 0` while the
daemon had lost 15,990 rows, because it read a bucket key the daemon does not
publish. These tests pin the corrected contract:

  * a missing `by_source` block is an attribution failure, never "zero";
  * either counter family moving fails the window;
  * the reported rate must be the held rate, not a free-running one.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import soak_rate  # noqa: E402


def test_parse_buckets_reads_by_source():
    stats = {"by_source": [{"name": "capture_etw", "dropped": 7}, {"name": "capture_fim", "dropped": 0}]}
    assert soak_rate.parse_buckets(stats) == {"capture_etw": 7, "capture_fim": 0}


def test_parse_buckets_absent_is_none_not_empty():
    # The exact defect that produced the false PASS: absent schema key.
    assert soak_rate.parse_buckets({}) is None
    assert soak_rate.parse_buckets({"buckets": []}) is None
    assert soak_rate.parse_buckets({"sources": []}) is None


def test_delta_reports_only_moved_counters():
    assert soak_rate.delta({"a": 1, "b": 5}, {"a": 4, "b": 5}) == {"a": 3}
    assert soak_rate.delta({}, {"a": 2}) == {"a": 2}


def test_verdict_passes_clean_window():
    v = soak_rate.verdict(target=4000, achieved=4010.0, per_source={}, integrity={})
    assert v["ok"] is True
    assert v["reasons"] == []


def test_verdict_fails_on_unattributable_window():
    v = soak_rate.verdict(target=4000, achieved=4010.0, per_source=None, integrity={})
    assert v["ok"] is False
    assert "no by_source buckets" in v["reasons"][0]


def test_verdict_fails_on_per_source_delta():
    v = soak_rate.verdict(target=4000, achieved=4010.0, per_source={"capture_fim": 12}, integrity={})
    assert v["ok"] is False
    assert v["drops_total"] == 12


def test_verdict_fails_on_integrity_delta_even_without_source_delta():
    # The daemon's periodic snapshot can move before the bucket view does; the
    # window must not pass until both agree.
    v = soak_rate.verdict(target=4000, achieved=4010.0, per_source={}, integrity={"queue_dropped_total": 9})
    assert v["ok"] is False
    assert v["integrity_total"] == 9


def test_verdict_fails_when_rate_was_not_held():
    v = soak_rate.verdict(target=4000, achieved=3831.0, per_source={}, integrity={})
    assert v["ok"] is False
    assert "below target" in v["reasons"][0]
