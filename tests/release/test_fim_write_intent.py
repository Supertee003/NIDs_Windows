"""FIM-WRITE-INTENT-001: read-only opens must not become write alerts.

The minifilter is C; there is no unit harness. These pins keep the two
mechanisms that matter in the source: the pre-create classification and the
post-op sentinel gate. The behavioural proof is the E5 canary.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "drivers" / "minifilter" / "aegis_minifilter_file.c"


def test_pre_create_classifies_write_intent() -> None:
    text = SOURCE.read_text(encoding="utf-8")
    assert "AegisWriteIntent" in text
    assert "DesiredAccess" in text
    assert "FILE_WRITE_DATA" in text
    assert "FILE_APPEND_DATA" in text
    assert "DELETE" in text
    assert "FILE_OVERWRITE_IF" in text


def test_post_op_skips_read_only_opens() -> None:
    text = SOURCE.read_text(encoding="utf-8")
    assert "if (ctx == NULL)" in text
    post = text.split("AegisPostOperation", 1)[1].split("AegisPreWrite", 1)[0]
    assert "UNREFERENCED_PARAMETER(ctx)" not in post
    assert "return FLT_POSTOP_FINISHED_PROCESSING;" in post
