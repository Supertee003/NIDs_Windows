"""PAYLOAD-ENVELOPE-V3-001: the brain's Tier-2 codec reads v3 frames.

`brain/canonical_event.py` is a second Python codec (Tier-2), separate from
the reference `shared/wire/wire_codec.py`. Nothing on the live path calls its
v3 entry points, so a broken v3 decode shipped unnoticed: the envelope
struct was unpacked into nine names while it carries ten fields (the pinned
reserved byte), which raised ValueError on every valid frame, and `encode_v3`
packed nine values into the same ten-field struct.

These tests pin the brain codec to the committed golden vectors so it cannot
drift from the Zig/Go/C++/reference-Python encoders again.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from brain import canonical_event as ce  # noqa: E402

VECTOR_DIR = REPO_ROOT / "tests" / "contracts" / "event_vectors" / "event_vectors"


def _vector(name: str) -> bytes:
    return (VECTOR_DIR / name).read_bytes()


@pytest.mark.parametrize(
    "name,completeness,payload_len",
    [
        ("event_v3_007.bin", ce.PAYLOAD_COMPLETE, 32),
        ("event_v3_008.bin", ce.PAYLOAD_TRUNCATED, 64),
        ("event_v3_009.bin", ce.PAYLOAD_METADATA_ONLY, 0),
    ],
)
def test_brain_decodes_committed_v3_vector(name, completeness, payload_len):
    ev = ce.decode(_vector(name))
    # The brain dataclass carries no version field (it re-derives the header
    # on encode), so identity is pinned on the decoded content instead.
    assert ev.struct_size == 128  # v3 in-memory layout tag
    assert ev.payload_completeness == completeness
    assert len(ev.payload_bytes) == payload_len


@pytest.mark.parametrize(
    "name",
    ["event_v3_007.bin", "event_v3_008.bin", "event_v3_009.bin"],
)
def test_brain_reencodes_v3_vector_byte_identically(name):
    raw = _vector(name)
    assert ce.encode_v3(ce.decode(raw)) == raw


def test_brain_rejects_non_zero_reserved_byte():
    raw = bytearray(_vector("event_v3_007.bin"))
    raw[ce.V3_BASE_SIZE + 3] = 0x01
    with pytest.raises(ValueError):
        ce.decode(bytes(raw))


def test_brain_v1_and_v2_vectors_stay_metadata_only():
    v2 = ce.decode(_vector("event_v2_006.bin"))
    assert len(v2.src_ipv6) == 16
    assert v2.payload_completeness == ce.PAYLOAD_UNAVAILABLE
    assert v2.payload_bytes == b""

    v1 = ce.decode(_vector("event_v1_001.bin"))
    assert v1.src_ipv6 == b"\x00" * 16
    assert v1.payload_bytes == b""


def test_brain_v3_vectors_match_the_reference_python_codec():
    """Two Python codecs, one schema: the brain must agree byte-for-byte."""
    from shared.wire.wire_codec import WireCodec

    for name in ("event_v3_007.bin", "event_v3_008.bin", "event_v3_009.bin"):
        raw = _vector(name)
        brain = ce.decode(raw)
        reference = WireCodec.decode_event(raw)
        assert reference is not None
        assert brain.event_id == reference.event_id
        assert brain.source_ip == reference.source_ip
        assert brain.dest_port == reference.dest_port
        assert brain.payload_bytes == reference.payload_bytes
