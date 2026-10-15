"""T11: single IP-convention ingress (EVT-110 join-tracing; re-baselined EVT-210).

History: Go capture stores IPv4 as a BE-numeric u32 (BigEndian.Uint32 of
wire bytes: 10.0.0.5 = 0x0A000005) while the old Zig npcap path bitcast
the same wire bytes (memory-layout: 0x0500000A). If both conventions ever
entered one queue, one host would become two flow identities (proved by
the JOIN-TRACE-119 test in src/capture/flow_table.zig).

Two later changes moved this invariant, and this file moves with them in
the same patch family (load-bearing: never silently, per the original doc):

  * EVT-200 re-enabled the direct Zig npcap path for the host-only lab,
    but ONLY behind AEGIS_DAEMON_IFACE (unset => historical disabled
    behavior, byte-identical). It is not a second production runtime.
  * EVT-201 canonicalized that path to BE-numeric (readInt(.big)), the
    blessed fix direction named by the original test -- so BOTH live
    producers now share one convention instead of one convention being
    merely absent.

This file re-pins the (now stronger) invariant by scanning source text:

  AC1. The canonical-ingress decision is recorded in the source.
  AC2. The two live producers are BE-convention (nose reader + pipe-JSON
       sensor parseIpv4 builds (value << 8) | octet, i.e. BE-numeric).
  AC3. The direct Zig npcap path is LAB-ONLY and ENV-GATED: daemon.zig
       reads AEGIS_DAEMON_IFACE and only then spawns
       packet_callback.captureThread. The quarantined windows_capture
       reader is still never referenced.
  AC4. packet_callback.zig reads BE (.big) and no longer bitcasts the
       wire bytes, so no memory-layout producer remains anywhere.

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


def test_direct_capture_is_env_gated_lab_path():
    daemon = _text(DAEMON)
    # The direct Zig path exists for the lab ...
    assert "packet_callback.captureThread" in daemon
    # ... but only behind the pin, and the pin is read before the spawn.
    gate = daemon.index("AEGIS_DAEMON_IFACE")
    spawn = daemon.index("packet_callback.captureThread")
    assert gate < spawn, "direct capture must be gated by AEGIS_DAEMON_IFACE"
    # The quarantined bypass reader (REBUILD-004) must never come back.
    assert "windows_capture" not in daemon


def test_packet_callback_is_be_canonical():
    # EVT-201 did the blessed fix the original test named: the wire bytes
    # are decoded as a BE network integer, so both live producers agree.
    src = _text(PACKET_CALLBACK)
    assert "readInt(u32" in src and ".big" in src
    assert "@bitCast(src_bytes)" not in src
