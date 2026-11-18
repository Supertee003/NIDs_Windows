"""Backend receipt contract tests.

These tests protect the distinction between an enforcement decision and a
confirmed host effect. A frontend or CLI must not render ENFORCED unless the
Rust PEP/provider receipt is complete and linkable.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "aegisctl"))

from api.control_api import is_valid_enforcement_receipt  # noqa: E402


VALID = {
    "status": "ENFORCED",
    "host_effect_confirmed": True,
    "provider": "wfp",
    "receipt_version": 1,
    "request_id": 10,
    "event_id": 20,
    "policy_id": 30,
    "filter_id": 40,
    "trace_id": 50,
    "audit_id": 60,
}


def test_complete_receipt_is_valid() -> None:
    assert is_valid_enforcement_receipt(VALID)


def test_decision_without_host_effect_is_not_valid() -> None:
    receipt = dict(VALID, host_effect_confirmed=False)
    assert not is_valid_enforcement_receipt(receipt)


def test_missing_forensic_identity_is_not_valid() -> None:
    receipt = dict(VALID)
    receipt.pop("audit_id")
    assert not is_valid_enforcement_receipt(receipt)


def test_simulated_status_is_not_valid() -> None:
    receipt = dict(VALID, status="SIMULATED")
    assert not is_valid_enforcement_receipt(receipt)


def test_malformed_numeric_fields_fail_closed() -> None:
    receipt = dict(VALID, filter_id="not-a-number")
    assert not is_valid_enforcement_receipt(receipt)


def test_non_dict_response_fails_closed() -> None:
    assert not is_valid_enforcement_receipt(None)
    assert not is_valid_enforcement_receipt("ENFORCED")

