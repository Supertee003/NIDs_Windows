"""CANARY-MAGIC-055: the canary magic has one value in three files.

0x43414E41 ("CANA") is declared in ips_canary.zig, ips_canary_order.zig,
and canary_progression.zig. The copies are intentional (ips_canary_order
is self-contained by design: imports std only, deterministic offline
tests), so they cannot share one constant without breaking that contract.
This pins all three to the same value instead: a silent edit to one copy
would split canary identity across modules. E1.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FILES = [
    "src/windows/ips_canary.zig",
    "src/windows/ips_canary_order.zig",
    "src/core/canary_progression.zig",
]
WANT = 0x43414E41


def magic_in(rel: str) -> int:
    text = (REPO / rel).read_text(encoding="utf-8")
    m = re.search(r"pub const CANARY_MAGIC:\s*u32\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*;", text)
    assert m, f"{rel} must declare CANARY_MAGIC"
    return int(m.group(1), 0)


def test_all_copies_share_one_value():
    values = {rel: magic_in(rel) for rel in FILES}
    assert set(values.values()) == {WANT}, values


def test_t18_canary_scope_constants_present():
    text = (REPO / "src/windows/ips_canary_order.zig").read_text(encoding="utf-8")
    assert "CANARY_IP_BASE" in text and "CANARY_PREFIX_LEN" in text
