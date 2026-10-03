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
