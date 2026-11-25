"""Pure, versioned canonical policy byte encoder (S4).

This module is an additive evidence/validation utility. It is intentionally
NOT wired into the legacy compiler hash, Ed25519 sidecar, or enforcement path.
See ``shared/policy/policy_canonical_v1.md`` for the byte contract.

The byte layout is fixed-width little-endian with explicit version headers and
length-prefixed UTF-8 strings. It therefore has no delimiter ambiguity and no
host struct padding/pointer dependence.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Mapping, Sequence
from typing import Any

RULE_MAGIC = b"PC01RULE"
SET_MAGIC = b"PC01SETS"
SIGN_MAGIC = b"PC01SIGN"

FORMAT_VERSION = 1
MAX_STRING_BYTES = 256
MAX_RULES = 64
MAX_CONDITIONS = 4
U64_MAX = 0xFFFFFFFFFFFFFFFF
I64_MIN = -(1 << 63)
I64_MAX = (1 << 63) - 1


class CanonicalPolicyError(ValueError):
    """Raised when an input cannot be represented in POLICY_CANONICAL_BYTES_V1."""


def _u32(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CanonicalPolicyError(f"{field} must be an integer")
    if value < 0 or value > 0xFFFFFFFF:
        raise CanonicalPolicyError(f"{field} must fit u32")
    return value


def _u16(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CanonicalPolicyError(f"{field} must be an integer")
    if value < 0 or value > 0xFFFF:
        raise CanonicalPolicyError(f"{field} must fit u16")
    return value


def _u8(value: Any, field: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CanonicalPolicyError(f"{field} must be an integer")
    if value < 0 or value > maximum:
        raise CanonicalPolicyError(f"{field} must be in 0..{maximum}")
    return value


def _u64(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CanonicalPolicyError(f"{field} must be an integer")
    if value < 0 or value > U64_MAX:
        raise CanonicalPolicyError(f"{field} must fit u64")
    return value


def _i64(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CanonicalPolicyError(f"{field} must be an integer")
    if value < I64_MIN or value > I64_MAX:
        raise CanonicalPolicyError(f"{field} must fit i64")
    return value


def _string_bytes(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise CanonicalPolicyError(f"{field} must be a string")
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_STRING_BYTES:
        raise CanonicalPolicyError(
            f"{field} exceeds {MAX_STRING_BYTES} UTF-8 bytes"
        )
    return encoded


def _length_prefixed(data: bytes) -> bytes:
    return struct.pack("<I", len(data)) + data


def canonical_rule_bytes_v1(rule: Mapping[str, Any]) -> bytes:
    """Encode one representation-B policy rule into canonical V1 bytes."""
    if not isinstance(rule, Mapping):
        raise CanonicalPolicyError("rule must be a mapping")

    conditions = rule.get("conditions", [])
    if not isinstance(conditions, Sequence) or isinstance(conditions, (str, bytes)):
        raise CanonicalPolicyError("conditions must be a sequence")
    condition_count = _u8(rule.get("condition_count", len(conditions)), "condition_count", MAX_CONDITIONS)
    if condition_count != len(conditions):
        raise CanonicalPolicyError("condition_count must equal len(conditions)")
    if condition_count > MAX_CONDITIONS:
        raise CanonicalPolicyError(f"condition_count exceeds {MAX_CONDITIONS}")

    enabled = rule.get("enabled")
    if not isinstance(enabled, bool):
        raise CanonicalPolicyError("enabled must be a boolean")

    out = bytearray()
    out += RULE_MAGIC
    out += struct.pack("<HH", FORMAT_VERSION, 0)  # version, reserved flags
    out += struct.pack(
        "<IBBBB",
        _u32(rule.get("id"), "id"),
        _u8(rule.get("priority"), "priority", 0xFF),
        _u8(rule.get("action"), "action", 5),
        1 if enabled else 0,
        condition_count,
    )
    out += _length_prefixed(_string_bytes(rule.get("name"), "name"))
    out += _length_prefixed(_string_bytes(rule.get("description", ""), "description"))

    for index, condition in enumerate(conditions[:condition_count]):
        if not isinstance(condition, Mapping):
            raise CanonicalPolicyError(f"conditions[{index}] must be a mapping")
        out += struct.pack(
            "<BBQQ",
            _u8(condition.get("field"), f"conditions[{index}].field", 8),
            _u8(condition.get("operator"), f"conditions[{index}].operator", 5),
            _u64(condition.get("value", 0), f"conditions[{index}].value"),
            _u64(condition.get("value2", 0), f"conditions[{index}].value2"),
        )
    return bytes(out)


def canonical_rule_set_bytes_v1(rules: Sequence[Mapping[str, Any]]) -> bytes:
    """Encode an ordered rule set into the versioned digest pre-image."""
    if not isinstance(rules, Sequence) or isinstance(rules, (str, bytes)):
        raise CanonicalPolicyError("rules must be a sequence")
    if not 1 <= len(rules) <= MAX_RULES:
        raise CanonicalPolicyError(f"rule count must be 1..{MAX_RULES}")
    out = bytearray(SET_MAGIC)
    out += struct.pack("<HHI", FORMAT_VERSION, 0, len(rules))
    for index, rule in enumerate(rules):
        out += canonical_rule_bytes_v1(rule)
        # Keep the compiler's identity semantics explicit: rules are already
        # in canonical order before encoding. This helper never reorders.
        del index
    return bytes(out)


def policy_rule_set_digest_v1(rules: Sequence[Mapping[str, Any]]) -> bytes:
    """SHA-256 of the versioned rule-set pre-image."""
    return hashlib.sha256(canonical_rule_set_bytes_v1(rules)).digest()


def canonical_signature_bytes_v1(
    ir_hash: Any,
    policy_version: Any,
    expiry_ms: Any,
    rules: Sequence[Mapping[str, Any]],
    ir_magic: Any = 0x504F4C31,
    ir_version: Any = 1,
) -> bytes:
    """Encode the versioned signed-policy pre-image.

    ``ir_hash`` is carried as an explicit u64 input; legacy numeric JS fields
    are non-authoritative above ``2^53-1`` and must be passed as ints here.
    """
    if not isinstance(rules, Sequence) or isinstance(rules, (str, bytes)):
        raise CanonicalPolicyError("rules must be a sequence")
    if not 1 <= len(rules) <= MAX_RULES:
        raise CanonicalPolicyError(f"rule count must be 1..{MAX_RULES}")
    out = bytearray(SIGN_MAGIC)
    out += struct.pack("<HH", FORMAT_VERSION, 0)
    out += struct.pack(
        "<IHHQIq",
        _u32(ir_magic, "ir_magic"),
        _u16(ir_version, "ir_version"),
        len(rules),
        _u64(ir_hash, "ir_hash"),
        _u32(policy_version, "policy_version"),
        _i64(expiry_ms, "expiry_ms"),
    )
    for rule in rules:
        out += canonical_rule_bytes_v1(rule)
    return bytes(out)


def canonical_signature_digest_v1(
    ir_hash: Any,
    policy_version: Any,
    expiry_ms: Any,
    rules: Sequence[Mapping[str, Any]],
    ir_magic: Any = 0x504F4C31,
    ir_version: Any = 1,
) -> bytes:
    """SHA-256 of the versioned signed-policy pre-image."""
    return hashlib.sha256(
        canonical_signature_bytes_v1(
            ir_hash, policy_version, expiry_ms, rules, ir_magic, ir_version
        )
    ).digest()
