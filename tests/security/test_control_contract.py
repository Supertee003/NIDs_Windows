"""CTL-DOC-040: control_protocol.md v2 section matches protocol.zig.

The v1.0 doc section is FROZEN (command names block.request et al. that no
active component sends or accepts). The appended v2 section is the live
contract: its command table must equal protocol.zig's fromString map and
its roles must equal contract()'s required_role entries; the retired list
must contain exactly the dead v1 names (absent from the map). E1+E2.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DOC = REPO / "shared" / "protocol" / "control_protocol.md"
PROTO = REPO / "src" / "control" / "protocol.zig"

RETIRED = {
    "block.request",
    "unblock.request",
    "quarantine.request",
    "block_request",
    "enforce_push",
}

ALIASES = {"status", "health", "health.check", "version"}


def zig_map_names() -> set[str]:
    src = PROTO.read_text(encoding="utf-8")
    return set(re.findall(r'\.\{\s*\.name\s*=\s*"([^"]+)"\s*,\s*\.cmd', src))


def zig_contract_roles() -> dict[str, str]:
    src = PROTO.read_text(encoding="utf-8")
    pairs = re.findall(
        r'\.name\s*=\s*"([^"]+)"\s*,\s*\.required_role\s*=\s*\.(\w+)', src)
    return dict(pairs)


def doc_v2_table() -> dict[str, str]:
    text = DOC.read_text(encoding="utf-8")
    section = text.split("# Version 2 (ACTIVE", 1)[1]
    rows = {}
    for line in section.splitlines():
        m = re.match(r"\|\s*`([^`]+)`\s*\|\s*(\w+)\s*\|", line)
        if m:
            rows[m.group(1)] = m.group(2)
    return rows


def doc_retired() -> set[str]:
    text = DOC.read_text(encoding="utf-8")
    section = text.split("## Retired names", 1)[1].split("## ", 1)[0]
    return set(re.findall(r"`([^`]+)`", section))


def test_v2_table_equals_code_map():
    code = zig_map_names()
    documented = set(doc_v2_table())
    dotted = {n for n in code if "." in n} - ALIASES
    assert documented == dotted, (
        f"missing from doc: {sorted(dotted - documented)}; "
        f"stale in doc: {sorted(documented - dotted)}")


def test_v2_roles_match_contract():
    code_roles = zig_contract_roles()
    doc_roles = doc_v2_table()
    for name, role in doc_roles.items():
        assert name in code_roles, f"{name} has no contract() entry"
        assert code_roles[name].upper() == role, (name, code_roles[name], role)


def test_retired_names_are_dead_and_listed():
    code = zig_map_names()
    listed = doc_retired()
    assert RETIRED <= listed, f"retired names missing from doc: {sorted(RETIRED - listed)}"
    assert not (RETIRED & code), f"retired name accepted by daemon: {sorted(RETIRED & code)}"


def test_aliases_still_accepted():
    code = zig_map_names()
    assert ALIASES <= code, f"legacy alias lost: {sorted(ALIASES - code)}"


def test_v1_section_untouched_by_v2():
    text = DOC.read_text(encoding="utf-8")
    v1 = text.split("# Version 2 (ACTIVE", 1)[0]
    assert "**Version:** 1.0" in v1 and "**Status:** FROZEN" in v1
    assert "| `block.request` | OPERATE |" in v1
