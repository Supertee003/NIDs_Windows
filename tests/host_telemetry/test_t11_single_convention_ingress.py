"""T11: single IP-convention ingress (EVT-110 join-tracing, closed by EVT-119).

The join-tracing question: Go capture stores IPv4 as BE-numeric u32
(BigEndian.Uint32 of wire bytes: 10.0.0.5 = 0x0A000005) while the Zig
npcap path bitcasts the same wire bytes (memory-layout: 0x0500000A),
and every downstream join (flow table, correlator windows, anomaly
baselines, policy src_ip equality) keys the raw u32 convention-blind.
If both conventions ever entered one queue, one host would become two
flow identities (proved by the JOIN-TRACE-119 test in
src/capture/flow_table.zig) — missed joins, never false blocks.

Production is safe because exactly one convention enters the live
queue. This file pins that ingress invariant by scanning daemon.zig:

  AC1. The canonical-ingress decision is recorded in the source
       ("Go Nose is canonical network ingress").
  AC2. The daemon spawns the two BE-convention live producers: the Go
       nose pipe reader and the BE pipe-JSON sensor (parseIpv4 builds
       (value << 8) | octet, i.e. BE-numeric).
  AC3. The daemon never references the memory-layout producers: no
       packetCallback / packet_callback / captureThread spawn, no
       windows_capture import. (The single "nids_main" mention is a
       comment naming the legacy startup contract, not a spawn.)

Hazard visibility: src/pipeline/packet_callback.zig still bitcasts
(@bitCast(src_bytes)). That is intentional — the convention is pinned
by its BYTE-ORDER tests — and it is exactly why AC3 is load-bearing.
Canonicalizing that path to BE is the blessed fix direction IF the
direct Zig path is ever re-enabled; do it in the same patch as this
test update, never silently.

Read-only: scans source text, writes nothing to the tree.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DAEMON = REPO_ROOT / "src" / "daemon.zig"
PACKET_CALLBACK = REPO_ROOT / "src" / "pipeline" / "packet_callback.zig"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_canonical_ingress_decision_recorded():
    assert "Go Nose is canonical network ingress" in _text(DAEMON)


def test_live_producers_are_be_convention():
    daemon = _text(DAEMON)
    assert "nose_reader.runPipeReaderLoop" in daemon
    assert "legacy_capture.capture_packets" in daemon


def test_no_memory_layout_producer_in_daemon():
    daemon = _text(DAEMON)
    for symbol in (
        "packetCallback",
        "packet_callback",
        "captureThread",
        "windows_capture",
    ):
        assert symbol not in daemon, symbol


def test_bitcast_hazard_stays_visible():
    # If packet_callback.zig is ever canonicalized to BE-numeric, update
    # this test in the SAME patch (one schema, N codecs rule).
    assert "@bitCast(src_bytes)" in _text(PACKET_CALLBACK)
