"""B2-AUTH-076: shared-secret auth for the UDP brain loop (behavioral).

Any local process can send to 127.0.0.1:9999, so an unauthenticated
"TIER-1 VERIFIED" offer would reach the brain's block-request path.
With AEGIS_BRAIN_SECRET set on both ends the daemon attaches
"<64 hex HMAC-SHA256>.<body>" (bridge_init.formatBrainWire) and the
brain drops anything failing verification, counting it in
DROPPED_COUNT. HEALTH stays open by design (liveness only).

Pure-function tests (no sockets, no daemon, no files): the splitter
and verifier are format-level, so the fail-closed matrix is pinned
without flaky loopback I/O. E2.
"""
from __future__ import annotations

import hashlib
import hmac
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from brain.windows_brain import (  # noqa: E402
    split_brain_envelope,
    verify_brain_mac,
)

SECRET = b"aegis-brain-auth-golden-v1"
BODY = b'{"source":"zig_pipeline","src_ip":"10.0.0.11"}'
# Shared golden, also asserted by the Zig test in
# src/core/bridge_init.zig ("brain wire envelope carries the
# cross-language golden MAC"): neither tier may change the MAC
# algorithm, the hex case, or the "<hex>.<body>" framing alone.
GOLDEN_HEX = "d9f85d9f559cc451d738ce842d99b37872e9e23fb309651cc869671b864fb02b"
GOLDEN_WIRE = GOLDEN_HEX.encode("ascii") + b"." + BODY


def _mac(body: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, body, hashlib.sha256).hexdigest().encode("ascii")


def test_golden_wire_matches_the_cross_language_table():
    assert _mac(BODY, SECRET).decode("ascii") == GOLDEN_HEX


def test_valid_envelope_splits_and_verifies():
    mac, body = split_brain_envelope(GOLDEN_WIRE)
    assert mac == GOLDEN_HEX.encode("ascii")
    assert body == BODY
    assert verify_brain_mac(body, mac, SECRET) is True


def test_tampered_body_fails_verification():
    mac, _ = split_brain_envelope(GOLDEN_WIRE)
    assert verify_brain_mac(b'{"source":"zig_pipeline","src_ip":"10.0.0.99"}', mac, SECRET) is False


def test_wrong_secret_fails_verification():
    mac, body = split_brain_envelope(GOLDEN_WIRE)
    assert verify_brain_mac(body, mac, b"wrong-secret") is False


def test_tampered_mac_fails_verification():
    _, body = split_brain_envelope(GOLDEN_WIRE)
    bad = b"0" * 64
    assert bad != GOLDEN_HEX.encode("ascii")
    assert verify_brain_mac(body, bad, SECRET) is False


def test_legacy_wire_without_prefix_is_untouched():
    mac, body = split_brain_envelope(BODY)
    assert mac is None
    assert body == BODY


def test_health_probe_shape_is_legacy_wire():
    health = b'{"op":"HEALTH"}'
    mac, body = split_brain_envelope(health)
    assert mac is None
    assert body == health


def test_splitter_never_raises_on_garbage():
    for raw in (b"", b".", b"x" * 64, b"0" * 64, b"0" * 64 + b"!",
                b"{" + b"0" * 63 + b".", "héllo".encode("utf-8")):
        mac, body = split_brain_envelope(raw)
        assert mac is None
        assert body == raw


def test_verifier_never_raises_on_garbage():
    assert verify_brain_mac(b"", b"", SECRET) is False
    assert verify_brain_mac(BODY, b"zz", SECRET) is False
    assert verify_brain_mac(BODY, GOLDEN_HEX.encode("ascii"), b"") is False


def test_mac_is_lowercase_hex_of_fixed_width():
    mac, _ = split_brain_envelope(GOLDEN_WIRE)
    assert len(mac) == 64
    assert mac.decode("ascii") == mac.decode("ascii").lower()


def test_health_response_carries_auth_posture_never_the_value():
    # EVT-156: the supervisor-visible HEALTH payload reports AUTH posture
    # ("on"/"off") so `aegisctl bridge` can show it. The secret value must
    # never appear on the wire: assert schema + absence, not liveness.
    import json
    from unittest.mock import patch
    import brain.windows_brain as wb
    doc = wb._health_response()
    assert doc["component"] == "brain" and doc["state"] == "RUNNING"
    assert isinstance(doc["pid"], int) and isinstance(doc["uptime_ms"], int)
    assert doc["auth"] == ("on" if wb.BRAIN_AUTH_SECRET is not None else "off")
    blob = json.dumps(doc)
    assert "AEGIS_BRAIN_SECRET" not in blob
    with patch.object(wb, "BRAIN_AUTH_SECRET", b"test-secret-16byte"):
        assert wb._health_response()["auth"] == "on"
    with patch.object(wb, "BRAIN_AUTH_SECRET", None):
        assert wb._health_response()["auth"] == "off"


def test_health_names_every_drop_reason_and_the_pipe_state():
    # RB-017/C3: HEALTH names every shed cause. The append-only anomaly log is
    # bounded two ways (rate throttle, hard size ceiling) and both must read as
    # distinct reasons so an operator never has to guess.
    import brain.windows_brain as wb
    doc = wb._health_response()
    assert set(doc["drops"]) == {"bad_mac", "no_mac", "log_throttle", "log_size_cap"}
    assert all(isinstance(v, int) and v >= 0 for v in doc["drops"].values())
    pipe = doc["sensor_pipe"]
    assert set(pipe) == {"enabled", "transport", "state", "failed"}
    assert pipe["transport"] in ("cython", "ctypes")
    assert pipe["state"] in ("ok", "failing", "off")
    assert pipe["state"] == ("off" if not pipe["enabled"]
                             else ("failing" if pipe["failed"] else "ok"))


def test_log_throttle_is_counted_under_its_own_reason_only():
    # The burst cap on anomalous.json is not an authentication failure; it must
    # land in log_throttle alone, or HEALTH sends the operator to the wrong cause.
    from unittest.mock import patch
    import brain.windows_brain as wb
    before = dict(wb.DROP_REASONS)
    try:
        with patch.object(wb, "_log_window_start", wb.time.monotonic()), \
             patch.object(wb, "_log_window_count", wb.LOG_BURST_MAX):
            assert wb.anomaly_log_allowed() is False
        assert wb.DROP_REASONS["log_throttle"] == before["log_throttle"] + 1
        for reason, value in before.items():
            if reason != "log_throttle":
                assert wb.DROP_REASONS[reason] == value
    finally:
        wb.DROP_REASONS.update(before)


def test_size_cap_sheds_the_append_but_keeps_the_file_intact(tmp_path):
    # A tail-safe bound: once the anomaly log reaches its ceiling the append is
    # shed and counted, the existing file is never shrunk or renamed, and the
    # caller still gets an explicit status (so Case 2 can keep delivering).
    import json
    from unittest.mock import patch
    import brain.windows_brain as wb
    log = tmp_path / "anomalous.json"
    log.write_text('{"seed":1}\n', encoding="utf-8")
    ceiling = log.stat().st_size  # already at the ceiling
    before = dict(wb.DROP_REASONS)
    before_dropped = wb.DROPPED_COUNT
    try:
        with patch.object(wb, "ANOMALOUS_MAX_BYTES", ceiling):
            status = wb.write_anomaly_log({"x": 1}, "t", "ALERT", "R", path=str(log))
        assert status == "SIZE_CAPPED"
        assert log.read_text(encoding="utf-8") == '{"seed":1}\n'  # never shrunk
        assert wb.DROP_REASONS["log_size_cap"] == before["log_size_cap"] + 1
        assert wb.DROPPED_COUNT == before_dropped + 1
        for reason, value in before.items():
            if reason != "log_size_cap":
                assert wb.DROP_REASONS[reason] == value
    finally:
        wb.DROP_REASONS.update(before)
        wb.DROPPED_COUNT = before_dropped


def test_size_cap_disabled_or_missing_file_does_not_block(tmp_path):
    # 0 means "no cap" (explicit opt-out), and a missing file cannot be over a
    # ceiling it does not have - both must still allow the append path.
    from unittest.mock import patch
    import brain.windows_brain as wb
    missing = tmp_path / "nope.json"
    assert wb._anomalous_log_capped(str(missing)) is False
    with patch.object(wb, "ANOMALOUS_MAX_BYTES", 0):
        assert wb._anomalous_log_capped(str(missing)) is False
    # a real write below the ceiling still lands
    log = tmp_path / "anomalous.json"
    with patch.object(wb, "ANOMALOUS_MAX_BYTES", 1024 * 1024), \
         patch.object(wb, "anomaly_log_allowed", return_value=True):
        assert wb.write_anomaly_log({"x": 1}, "t", "ALERT", "R", path=str(log)) == "WRITTEN"
    assert log.exists()
