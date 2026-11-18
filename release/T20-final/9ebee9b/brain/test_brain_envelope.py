"""BRAIN-AUTH-096: TIER-1 envelope HMAC contract pins.

split_brain_envelope / verify_brain_mac are the fail-closed gate between
unauthenticated UDP input and the block-request path: any local process can
send to 127.0.0.1:9999, so a forged envelope must never verify. Pure
functions, no sockets (import side-effect safety is pinned separately by
tests/brain/test_import_hygiene.py).
"""
import hashlib
import hmac

from brain.windows_brain import (
    BRAIN_MAC_LEN,
    split_brain_envelope,
    verify_brain_mac,
)

SECRET = b"test-secret-16byte"


def _mac_for(body: bytes) -> bytes:
    return hmac.new(SECRET, body, hashlib.sha256).hexdigest().encode("ascii")


def test_legacy_wire_without_dot_passes_through_untagged():
    assert split_brain_envelope(b'{"a":1}') == (None, b'{"a":1}')
    assert split_brain_envelope(b"") == (None, b"")


def test_short_or_malformed_input_is_legacy_never_raises():
    assert split_brain_envelope(b"abc") == (None, b"abc")
    # 64 hex chars but no dot separator -> legacy, not a mac.
    assert split_brain_envelope(b"0" * 64) == (None, b"0" * 64)
    # Non-hex prefix with dot at 64 -> legacy.
    assert split_brain_envelope(b"z" * 64 + b".{}") == (None, b"z" * 64 + b".{}")


def test_wellformed_envelope_splits_mac_and_body():
    body = b'{"offer":"x"}'
    raw = _mac_for(body) + b"." + body
    assert len(raw) > BRAIN_MAC_LEN
    mac, out = split_brain_envelope(raw)
    assert mac == _mac_for(body)
    assert out == body


def test_verify_round_trip_accepts():
    body = b'{"offer":"x"}'
    assert verify_brain_mac(body, _mac_for(body), SECRET) is True


def test_verify_rejects_tampered_body_and_wrong_secret():
    body = b'{"offer":"x"}'
    good = _mac_for(body)
    assert verify_brain_mac(b'{"offer":"y"}', good, SECRET) is False
    assert verify_brain_mac(body, good, b"wrong-secret-0000") is False
    assert verify_brain_mac(body, b"0" * 64, SECRET) is False


def test_verify_accepts_uppercase_hex_and_never_raises():
    body = b"{}"
    assert verify_brain_mac(body, _mac_for(body).upper(), SECRET) is True
    assert verify_brain_mac(None, None, None) is False  # type: ignore[arg-type]
