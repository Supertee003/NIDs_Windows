"""REG-REARM-060: registry re-arm failure is surfaced, never silent (static).

RegNotifyChangeKeyValue is one-shot: after each fire it must be reissued
or the key goes blind with no further events. The reissue result used to
be discarded (`_ = ...`), so a revoked key or closed handle ended
coverage silently. The result is now checked and warned. The native path
needs real HKLM keys and is never unit-run; this pins the source
contract so the discard cannot creep back. E1.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MONITOR = REPO / "src" / "windows" / "registry_monitor.zig"


def src() -> str:
    return MONITOR.read_text(encoding="utf-8")


def test_reissue_result_is_checked():
    discarded = [
        line.strip() for line in src().splitlines()
        if line.strip().startswith("_ = RegNotifyChangeKeyValue")
    ]
    assert discarded == [], f"silent re-arm discards: {discarded}"


def test_rearm_failure_warns_with_key():
    text = src()
    assert "re-arm failed" in text
    assert "unwatched until restart" in text
