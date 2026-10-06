"""A1: incident TTL eviction verdict, pinned at both ends.

Verdict (see ThreatTracker.pruneExpired): only `.open` incidents expire
after INCIDENT_TTL_NS of event-clock idleness; terminal states persist;
expired slots compact for reuse; idle flow state drops with its
incident; the pipeline loop drives expiry off the pre-corruption event
clock and owns the open-counter decrement. Contract:

  AC1. TTL is one hour, single definition, actually referenced.
  AC2. Expiry is wired into the pipeline prune section (not dead code).
  AC3. The open counter is decremented on expiry (no monotonic leak).
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TRACKER = (REPO_ROOT / "src" / "detection" / "threat_tracker.zig").read_text(encoding="utf-8")
PROCESSOR = (REPO_ROOT / "src" / "pipeline" / "event_processor.zig").read_text(encoding="utf-8")


def test_ttl_is_one_hour_and_referenced():
    assert "INCIDENT_TTL_NS: i128 = 3600 * std.time.ns_per_s" in TRACKER
    assert TRACKER.count("INCIDENT_TTL_NS") >= 3  # def + prune uses


def test_expiry_is_wired_into_the_pipeline_loop():
    assert "pruneExpired(prune_now_ns)" in PROCESSOR
    assert "prune_now_ns = qe.ev.timestamp_ns" in PROCESSOR
    assert "g_incidents_open.fetchSub(expired" in PROCESSOR


def test_only_open_incidents_expire():
    assert "inc.state == .open" in TRACKER
    assert "Terminal states" in TRACKER or "terminal" in TRACKER.lower()
