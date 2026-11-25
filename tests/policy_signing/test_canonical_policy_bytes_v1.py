"""S4: Python consumes the shared canonical policy byte vectors read-only."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from brain.policy_canonical_v1 import (
    CanonicalPolicyError,
    canonical_rule_bytes_v1,
    canonical_signature_digest_v1,
    policy_rule_set_digest_v1,
)

REPO = Path(__file__).resolve().parents[2]
VECTOR_PATH = REPO / "shared" / "vectors" / "policy_canonical_v1.json"


def _load_manifest() -> dict[str, Any]:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def _hex_u64(text: str) -> int:
    assert text.startswith("0x")
    return int(text[2:], 16)


def _to_rule(raw: dict[str, Any]) -> dict[str, Any]:
    conditions = [
        {
            "field": cond["field"],
            "operator": cond["operator"],
            "value": _hex_u64(cond["value"]),
            "value2": _hex_u64(cond["value2"]),
        }
        for cond in raw["conditions"]
    ]
    assert raw["condition_count"] == len(conditions)
    return {
        "id": raw["id"],
        "name": raw["name"],
        "description": raw["description"],
        "priority": raw["priority"],
        "action": raw["action"],
        "enabled": raw["enabled"],
        "conditions": conditions,
    }


def test_vector_manifest_is_v1() -> None:
    manifest = _load_manifest()
    assert manifest["format"] == "POLICY_CANONICAL_BYTES_V1"
    assert len(manifest["cases"]) >= 4


@pytest.mark.parametrize("case", _load_manifest()["cases"], ids=lambda c: c["id"])
def test_python_matches_shared_canonical_policy_vectors(case: dict[str, Any]) -> None:
    rules = [_to_rule(raw) for raw in case["rules"]]
    rule_hex = [canonical_rule_bytes_v1(rule).hex() for rule in rules]
    assert rule_hex == case["expected_rule_bytes_hex"]
    assert policy_rule_set_digest_v1(rules).hex() == case["expected_rule_set_digest_hex"]
    assert (
        canonical_signature_digest_v1(
            _hex_u64(case["ir_hash"]),
            case["policy_version"],
            case["expiry_ms"],
            rules,
            case["ir_magic"],
            case["ir_version"],
        ).hex()
        == case["expected_signature_digest_hex"]
    )


def test_encoder_rejects_non_representable_inputs() -> None:
    base: dict[str, Any] = {
        "id": 1,
        "name": "r",
        "description": "",
        "priority": 1,
        "action": 1,
        "enabled": True,
        "conditions": [],
    }
    with pytest.raises(CanonicalPolicyError, match="256 UTF-8 bytes"):
        canonical_rule_bytes_v1({**base, "name": "x" * 257})
    with pytest.raises(CanonicalPolicyError, match="fit u64"):
        canonical_rule_bytes_v1(
            {
                **base,
                "conditions": [
                    {"field": 0, "operator": 0, "value": 1 << 64, "value2": 0}
                ],
            }
        )
    with pytest.raises(CanonicalPolicyError, match="0..5"):
        canonical_rule_bytes_v1({**base, "action": 6})
