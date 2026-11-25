"""Generate the shared POLICY_CANONICAL_BYTES_V1 vector manifest.

Producer-owned artifact: tests read `shared/vectors/policy_canonical_v1.json`
but never rewrite it. Regenerate explicitly with::

    python tools/generate_policy_canonical_vectors.py --write
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from brain.policy_canonical_v1 import (  # noqa: E402
    canonical_rule_bytes_v1,
    canonical_signature_digest_v1,
    policy_rule_set_digest_v1,
)

VECTOR_PATH = ROOT / "shared" / "vectors" / "policy_canonical_v1.json"


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _json_rule(rule: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": rule["id"],
        "name": rule["name"],
        "priority": rule["priority"],
        "action": rule["action"],
        "enabled": rule["enabled"],
        "description": rule["description"],
        "condition_count": len(rule["conditions"]),
        "conditions": [
            {
                "field": c["field"],
                "operator": c["operator"],
                "value": _hex(c["value"]),
                "value2": _hex(c["value2"]),
            }
            for c in rule["conditions"]
        ],
    }
    return result


def build_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []

    minimal = {
        "id": 1,
        "name": "r",
        "priority": 1,
        "action": 1,
        "enabled": True,
        "description": "",
        "conditions": [
            {"field": 0, "operator": 0, "value": 1, "value2": 0},
        ],
    }
    cases.append(
        {
            "id": "minimal",
            "rules": [minimal],
            "ir_hash": 0x0123456789ABCDEF,
            "policy_version": 5,
            "expiry_ms": 9_999_999_999_999,
        }
    )

    delimiters = {
        "id": 0xFFFFFFFF,
        "name": "a\x1fb\n\x00✓日",
        "priority": 255,
        "action": 2,
        "enabled": False,
        "description": "tail\x1fz\x00\n",
        "conditions": [
            {
                "field": 3,
                "operator": 4,
                "value": 0x20000000000000,
                "value2": 0xFFFFFFFFFFFFFFFF,
            },
            {"field": 8, "operator": 5, "value": 0, "value2": 0},
        ],
    }
    cases.append(
        {
            "id": "delimiters_unicode_nul",
            "rules": [delimiters],
            "ir_hash": 0xFFFFFFFFFFFFFFFF,
            "policy_version": 7,
            "expiry_ms": 1_700_000_000_000,
        }
    )

    maximum = {
        "id": 64,
        "name": "N" * 256,
        "priority": 0,
        "action": 5,
        "enabled": True,
        "description": "D" * 256,
        "conditions": [
            {"field": 0, "operator": 0, "value": 0, "value2": 0},
            {"field": 5, "operator": 1, "value": 0x20000000000000, "value2": 0},
            {"field": 8, "operator": 4, "value": 0xFFFFFFFFFFFFFFFE, "value2": 0xFFFFFFFFFFFFFFFF},
            {"field": 8, "operator": 5, "value": 0xDEADBEEFCAFEBABE, "value2": 0},
        ],
    }
    cases.append(
        {
            "id": "max_strings_and_u64_boundary",
            "rules": [maximum],
            "ir_hash": 0x20000000000000,
            "policy_version": 0,
            "expiry_ms": 0,
        }
    )

    first = {
        "id": 7,
        "name": "first",
        "priority": 10,
        "action": 0,
        "enabled": True,
        "description": "one",
        "conditions": [{"field": 1, "operator": 0, "value": 5, "value2": 0}],
    }
    second = {
        "id": 8,
        "name": "second\x1f✓",
        "priority": 20,
        "action": 4,
        "enabled": False,
        "description": "two\nthree",
        "conditions": [],
    }
    cases.append(
        {
            "id": "two_rules_order",
            "rules": [first, second],
            "ir_hash": 0xDEADBEEFCAFEBABE,
            "policy_version": 9,
            "expiry_ms": 123_456_789,
        }
    )
    return cases


def build_manifest() -> dict[str, Any]:
    cases = build_cases()
    out_cases: list[dict[str, Any]] = []
    for case in cases:
        rules = case["rules"]
        json_rules = [_json_rule(rule) for rule in rules]
        out_cases.append(
            {
                "id": case["id"],
                "rules": json_rules,
                "ir_hash": _hex(case["ir_hash"]),
                "policy_version": case["policy_version"],
                "expiry_ms": case["expiry_ms"],
                "ir_magic": 0x504F4C31,
                "ir_version": 1,
                "expected_rule_bytes_hex": [
                    canonical_rule_bytes_v1(rule).hex() for rule in rules
                ],
                "expected_rule_set_digest_hex": policy_rule_set_digest_v1(rules).hex(),
                "expected_signature_digest_hex": canonical_signature_digest_v1(
                    case["ir_hash"],
                    case["policy_version"],
                    case["expiry_ms"],
                    rules,
                ).hex(),
            }
        )
    return {
        "format": "POLICY_CANONICAL_BYTES_V1",
        "spec": "shared/policy/policy_canonical_v1.md",
        "generator": "tools/generate_policy_canonical_vectors.py",
        "note": "Tests are read-only; regenerate only via the explicit --write flag.",
        "cases": out_cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="write the committed vector manifest (tests never do this)",
    )
    args = parser.parse_args()
    payload = json.dumps(build_manifest(), indent=2, sort_keys=True) + "\n"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    if args.write:
        VECTOR_PATH.parent.mkdir(parents=True, exist_ok=True)
        VECTOR_PATH.write_text(payload, encoding="utf-8", newline="\n")
        print(f"wrote {VECTOR_PATH.relative_to(ROOT)}")
    print(f"vector_sha256={digest}")
    print(f"cases={len(build_manifest()['cases'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
