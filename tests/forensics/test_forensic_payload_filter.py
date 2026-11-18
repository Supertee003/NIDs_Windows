"""FORENSIC-CONTAINS-001: the ring must be searchable by the text it carries.

`forensics.list` has two byte filters and they answer different questions:

* `payload_prefix` compares the stored record bytes **from byte 0**. On capture
  rows byte 0 is the L2 header, so a readable string can never be a prefix --
  correct, but it made the filter look broken: an operator typed text, got
  `records_matched: 0`, and had no way to tell "not retained" from "no match".
* `payload_contains` (this slice) searches the payload span for a byte sequence
  anywhere, which is the question an operator actually asks: *which record
  carries this text?*

Contract pinned here:
  AC1. The handler parses `payload_contains` and filters with a substring search
       over exactly the payload span (never the header, never past payload_len).
  AC2. The CLI exposes `--field payload_contains` and sends that field.
  AC3. `payload_prefix` keeps its raw-bytes-from-zero meaning and its help text
       says so, so the two filters cannot be confused again.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
HANDLER = REPO_ROOT / "src" / "control" / "handler_registry.zig"
CLI = REPO_ROOT / "tools" / "aegisctl.py"


def test_handler_parses_payload_contains() -> None:
    source = HANDLER.read_text(encoding="utf-8")
    assert '"payload_contains"' in source, "forensics.list must read payload_contains"
    assert "requested_contains" in source


def test_handler_searches_the_payload_span_only() -> None:
    source = HANDLER.read_text(encoding="utf-8")
    assert (
        "std.mem.indexOf(u8, record[payload_start..payload_end], requested_contains)" in source
    ), "payload_contains must search exactly the payload span"


def test_cli_exposes_the_field() -> None:
    source = CLI.read_text(encoding="utf-8")
    assert 'elif field == "payload_contains":' in source
    assert 'payload = {"payload_contains": value}' in source
    assert "payload_contains = byte sequence anywhere in the payload" in source


def test_prefix_help_still_says_raw_bytes() -> None:
    source = CLI.read_text(encoding="utf-8")
    assert "payload_prefix = raw record-bytes prefix from byte 0" in source
