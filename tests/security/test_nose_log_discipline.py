"""LOG-FLOOD-062: nose hot path logs at debug, anomalies at warn (static).

The pipe reader thread formats these lines per frame: at capture rates,
info-level per-frame output floods the log sink and steals the reader's
own CPU. Volume stays observable via frames_read/submitted counters.
Reject/duplicate/non-monotonic/payload-failure lines must stay warn —
they signal data-plane anomalies, not routine flow. E1.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
READER = REPO / "src" / "capture" / "nose_pipe_reader.zig"


def src() -> str:
    return READER.read_text(encoding="utf-8")


def test_routine_per_frame_lines_are_debug():
    text = src()
    assert 'std.log.info("[NOSE PIPE] frame received' not in text
    assert 'std.log.info("[NOSE PIPE] canonical event submitted' not in text
    assert 'std.log.debug("[NOSE PIPE] frame received' in text
    assert 'std.log.debug("[NOSE PIPE] canonical event submitted' in text


def test_anomaly_lines_stay_warn():
    text = src()
    for needle in (
        "rejected frame length",
        "duplicate event_id",
        "non-monotonic event_id",
        "frame payload read failed",
        "canonical frame rejected by deserializer",
    ):
        assert f'std.log.warn("[NOSE PIPE] {needle}' in text, needle
