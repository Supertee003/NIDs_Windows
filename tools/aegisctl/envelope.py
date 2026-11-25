"""Control-plane v2 request envelope builder.

CONTROL-REPLAY-001: the active Zig control server requires every request to
carry a protocol version, a wall-clock freshness timestamp and a 16-byte
single-use nonce. This module is the single Python-side builder so no client
can forget a field. Roles are deliberately absent: the daemon derives the
caller role from the impersonated Windows token.
"""
from __future__ import annotations

import json
import secrets
import time
from typing import Any, Dict, Mapping

CONTROL_PROTOCOL_VERSION = 2
NONCE_BYTES = 16


def build_v2_envelope(
    command: str, payload: Mapping[str, Any] | None = None
) -> Dict[str, Any]:
    """Build the v2 envelope dict; callers that audit the nonce use this exact object."""
    return {
        "command": command,
        "payload": dict(payload or {}),
        "protocol_version": CONTROL_PROTOCOL_VERSION,
        "request_id": secrets.token_hex(NONCE_BYTES),
        "nonce": secrets.token_hex(NONCE_BYTES),
        "issued_at_ms": int(time.time() * 1000),
    }


def serialize_envelope(envelope: Mapping[str, Any]) -> bytes:
    """Serialize one v2 control envelope as UTF-8 JSON bytes."""
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def build_v2_request(command: str, payload: Mapping[str, Any] | None = None) -> bytes:
    """Return the UTF-8 JSON bytes of one v2 control request."""
    return serialize_envelope(build_v2_envelope(command, payload))
