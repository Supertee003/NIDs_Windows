"""CONTRACT-01 (Canonical Event) ContextFlags bit2 pin.

The v1 109-byte wire has no IPv6 address fields. When Go Nose captures an
IPv6 packet it embeds only the first 4 bytes of each address and MUST set
ContextFlags bit2 (ipv6_truncated). Zig declares the same bit. Any consumer
that treats a bit2 identity as IPv4 aliases unrelated hosts (e.g. all
fe80::/10 link-locals collapse).

Pinned here:
  V6-1. Go defines ContextV6Truncated == 1<<2.
  V6-2. Go sets it on the IPv6 capture branch (and only needs it there).
  V6-3. Zig declares CONTEXT_V6_TRUNCATED == 1<<2 with the no-IPv4 rule.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GO_CANONICAL = REPO_ROOT / "nose" / "canonical.go"
GO_CAPTURE = REPO_ROOT / "nose" / "capture.go"
ZIG_CANONICAL = REPO_ROOT / "src" / "contract" / "canonical_event.zig"

EXPECTED_BIT = 2


def test_go_defines_v6_truncated_bit():
    src = GO_CANONICAL.read_text(encoding="utf-8")
    match = re.search(r"ContextV6Truncated\s+uint32\s*=\s*1\s*<<\s*(\d+)", src)
    assert match, "nose/canonical.go must define ContextV6Truncated"
    assert int(match.group(1)) == EXPECTED_BIT


def test_go_capture_sets_v6_bit_on_ipv6_branch():
    src = GO_CAPTURE.read_text(encoding="utf-8")
    ipv6_branch = src.split("case *layers.IPv6:", 1)
    assert len(ipv6_branch) == 2, "IPv6 capture branch must exist"
    # Bound the search to the L3 identity block (before transport parsing).
    l3_block = ipv6_branch[1].split("// --- transport ports ---", 1)[0]
    assert "ContextV6Truncated" in l3_block, (
        "the IPv6 branch must mark ContextV6Truncated on every v6 event"
    )


def test_zig_declares_v6_truncated_bit_with_no_ipv4_rule():
    src = ZIG_CANONICAL.read_text(encoding="utf-8")
    match = re.search(r"CONTEXT_V6_TRUNCATED\s*:\s*u32\s*=\s*1\s*<<\s*(\d+)", src)
    assert match, "canonical_event.zig must declare CONTEXT_V6_TRUNCATED"
    assert int(match.group(1)) == EXPECTED_BIT
    assert "must never be treated as IPv4" in src or "must not" in src.lower()


# RB-021-NOSE-FLAGS: the TCP-flags lane is additive ContextFlags metadata.
# It must be identical in every codec even though only Go writes it and Zig
# consumes it; the wire layout itself stays 109/133 bytes.
TCP_FLAGS_SHIFT = 16
TCP_FLAGS_VALID_BIT = 24


def test_tcp_flags_lane_constants_across_codecs():
    go_src = GO_CANONICAL.read_text(encoding="utf-8")
    assert re.search(r"ContextTCPFlagsShift\s+uint32\s*=\s*16", go_src)
    assert re.search(r"ContextTCPFlagsValid\s+uint32\s*=\s*1\s*<<\s*24", go_src)
    assert "func (e *CanonicalEvent) SetTCPFlags" in go_src
    assert "func (e *CanonicalEvent) TCPFlags" in go_src

    zig_src = ZIG_CANONICAL.read_text(encoding="utf-8")
    assert re.search(r"CONTEXT_TCP_FLAGS_SHIFT\s*:\s*u5\s*=\s*16", zig_src)
    assert re.search(r"CONTEXT_TCP_FLAGS_VALID\s*:\s*u32\s*=\s*1\s*<<\s*24", zig_src)
    assert "pub fn setTcpFlags" in zig_src
    assert "pub fn getTcpFlags" in zig_src

    py_src = (REPO_ROOT / "shared" / "wire" / "wire_codec.py").read_text(encoding="utf-8")
    assert f"CONTEXT_TCP_FLAGS_SHIFT: int = {TCP_FLAGS_SHIFT}" in py_src
    assert f"CONTEXT_TCP_FLAGS_VALID: int = 1 << {TCP_FLAGS_VALID_BIT}" in py_src

    brain_src = (REPO_ROOT / "brain" / "canonical_event.py").read_text(encoding="utf-8")
    assert f"CONTEXT_TCP_FLAGS_SHIFT = {TCP_FLAGS_SHIFT}" in brain_src
    assert f"CONTEXT_TCP_FLAGS_VALID = 1 << {TCP_FLAGS_VALID_BIT}" in brain_src

    cpp_src = (REPO_ROOT / "shared" / "wire" / "wire_codec.h").read_text(encoding="utf-8")
    assert "CONTEXT_TCP_FLAGS_SHIFT = 16" in cpp_src
    assert "CONTEXT_TCP_FLAGS_VALID = (1u << 24)" in cpp_src


def test_python_codec_round_trips_tcp_flags_lane():
    from shared.wire.wire_codec import (
        CONTEXT_TCP_FLAGS_MASK,
        CONTEXT_TCP_FLAGS_VALID,
        CanonicalEvent,
        WireCodec,
    )

    flags = 0x29  # FIN|PSH|URG (R9007)
    lane = CONTEXT_TCP_FLAGS_VALID | (flags << TCP_FLAGS_SHIFT)
    ev = CanonicalEvent(
        source_ip=0x0A000005,
        dest_ip=0xC0A80101,
        source_port=40000,
        dest_port=443,
        protocol=6,
        context_flags=lane,
    )
    wire = WireCodec.encode_event(ev)
    assert len(wire) == 109
    back = WireCodec.decode_event(wire)
    assert back is not None
    assert back.context_flags == lane
    assert (back.context_flags & CONTEXT_TCP_FLAGS_MASK) != 0
    assert (back.context_flags & CONTEXT_TCP_FLAGS_VALID) != 0
