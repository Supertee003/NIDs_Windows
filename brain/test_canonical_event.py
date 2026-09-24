"""CONTRACT-01 cross-language golden test (Python side).

Reproduces the frozen T2 golden vector from
src/contract/canonical_event.zig. Fails if the Python codec diverges.
"""
import pytest

from brain.canonical_event import (
    EVENT_CUSTOM,
    EVENT_TYPE,
    POLICY_ACTION,
    SOURCE,
    CanonicalEvent,
    decode,
    encode,
)

GOLDEN = bytes([
    0x31, 0x47, 0x45, 0x41, 0x01, 0x00, 0x80, 0x00,
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x09, 0x64, 0x01, 0xA8, 0xC0, 0x00, 0xC0, 0x0A,
    0x0A, 0x1F, 0xAC, 0xBB, 0x01, 0xBE, 0xBA, 0xFE,
    0xCA, 0xEF, 0xBE, 0xAD, 0xDE, 0x06, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x04, 0x03,
    0x02, 0x01, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xDC, 0x05, 0x00, 0x00, 0xAD, 0xDE,
    0xEF, 0xBE, 0x0D, 0xF0, 0xAD, 0x0B, 0x01, 0x01,
    0x04, 0x03, 0x00, 0x00, 0x00, 0x92, 0x10, 0x00,
    0x00, 0x20, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x7B, 0x00, 0x00, 0x5F,
])
assert len(GOLDEN) == 109


def test_golden_vector_decodes():
    ev = decode(GOLDEN)
    assert ev.source == SOURCE["npcap_sensor"] == 9
    assert ev.event_id == 0x1122334455667788
    assert ev.source_ip == 0xC0A80164
    assert ev.event_type == EVENT_TYPE["match"] == 1
    assert ev.policy_action == POLICY_ACTION["alert"] == 1
    assert ev.payload_length == 1500
    assert ev.reserved[15] == 95  # confidence


def test_golden_vector_round_trip():
    assert encode(decode(GOLDEN)) == GOLDEN


def test_ordinals_match_zig():
    assert SOURCE["registry_sensor"] == 15
    assert SOURCE["replay_sensor"] == 16
    assert SOURCE["external"] == 255
    assert EVENT_TYPE["forward"] == 2
    assert EVENT_CUSTOM == 0xFFFFFFFF
    assert POLICY_ACTION["block"] == 2
    assert POLICY_ACTION["log_only"] == 5


def test_decode_rejects_violations():
    with pytest.raises(ValueError):
        decode(GOLDEN[:50])
    bad = bytearray(GOLDEN)
    bad[0] ^= 0xFF
    with pytest.raises(ValueError):
        decode(bytes(bad))
    bad = bytearray(GOLDEN)
    bad[32] = 17
    with pytest.raises(ValueError):
        decode(bytes(bad))
    bad = bytearray(GOLDEN)
    bad[86] = 6
    with pytest.raises(ValueError):
        decode(bytes(bad))
