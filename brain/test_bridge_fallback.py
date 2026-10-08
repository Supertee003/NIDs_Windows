"""BRIDGE-096: Cython-or-Python dispatch fallback pins.

brain.aegis_brain_cython.bridge selects the compiled extension when present
and pure-Python fallbacks otherwise. These pins force the fallback path via
monkeypatch (deterministic even on hosts with the .pyd built) plus direct
coverage of the pure functions. No I/O, no sockets.
"""
import pytest

from brain.aegis_brain_cython import bridge


@pytest.fixture
def fallback_only(monkeypatch):
    monkeypatch.setattr(bridge, "CYTHON_AVAILABLE", False)
    return bridge


def test_fallback_scan_match_and_miss(fallback_only):
    idx, matched = fallback_only.scan_payload(b"GET /admin", [b"XSS", b"admin"])
    assert (idx, matched) == (1, b"admin")
    assert fallback_only.scan_payload(b"GET /", [b"XSS"]) == (-1, None)


def test_fallback_severity_mapping(fallback_only):
    assert fallback_only.get_severity("Low") == 0
    assert fallback_only.get_severity("Critical") == 3
    assert fallback_only.get_severity("Bogus") == -1


def test_fallback_defcon_ladder(fallback_only):
    assert fallback_only.compute_defcon(1, 0, 0, 0) == 1
    assert fallback_only.compute_defcon(0, 3, 0, 0) == 2
    assert fallback_only.compute_defcon(0, 0, 10, 0) == 3
    assert fallback_only.compute_defcon(0, 0, 1, 0) == 4
    assert fallback_only.compute_defcon(0, 0, 0, 0) == 5


def test_fallback_field_extract_and_size(fallback_only):
    assert fallback_only.extract_field(b'{"a": "b"}', "a") == "b"
    assert fallback_only.extract_field(b"not-json", "a") is None
    assert fallback_only.check_payload_size(b"x" * 11, 10) is True
    assert fallback_only.check_payload_size(b"x" * 10, 10) is False
