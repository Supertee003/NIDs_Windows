"""Authoritative operator-facing contract helpers.

This module is presentation-safe: it never authorizes or performs host
mutation.  It only validates/projections data already attested by the Zig
control plane.
"""
from __future__ import annotations

from typing import Any, Mapping

POLICY_ACTION_ORDINALS = {
    "ALLOW": 0,
    "ALERT": 1,
    "BLOCK": 2,
    "QUARANTINE": 3,
    "RATE_LIMIT": 4,
    "LOG_ONLY": 5,
}

# PEP response decisions are a different namespace from policy actions.
PEP_DECISION_ORDINALS = {
    "ALLOW": 0,
    "BLOCK": 1,
    "RATE_LIMIT": 2,
    "QUARANTINE": 3,
    "ESCALATE": 4,
    "DROP": 5,
}

RECEIPT_VERSION = 1
CONFIRMED_STATUS = "enforced"


def validate_enforcement_receipt(receipt: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """Return whether a receipt is safe to display as a confirmed host effect."""
    required = ("request_id", "event_id", "policy_id", "decision", "status", "provider")
    errors = [f"missing:{key}" for key in required if key not in receipt]
    if errors:
        return False, errors

    for key in ("request_id", "event_id", "policy_id", "trace_id", "audit_id"):
        if key in receipt and int(receipt.get(key) or 0) < 0:
            errors.append(f"negative:{key}")
    if int(receipt.get("request_id") or 0) == 0:
        errors.append("zero:request_id")
    if int(receipt.get("event_id") or 0) == 0:
        errors.append("zero:event_id")

    version = int(receipt.get("receipt_version", receipt.get("version", 0)) or 0)
    status = str(receipt.get("status", "")).lower()
    confirmed = bool(receipt.get("host_effect_confirmed", False))
    if version not in (0, RECEIPT_VERSION):
        errors.append("unsupported:receipt_version")
    if confirmed and status != CONFIRMED_STATUS:
        errors.append("host_effect_requires_enforced")
    if status == CONFIRMED_STATUS:
        for key in ("filter_id", "trace_id", "audit_id"):
            if int(receipt.get(key) or 0) == 0:
                errors.append(f"zero:{key}")
        if not str(receipt.get("provider", "")):
            errors.append("empty:provider")
        if not confirmed:
            errors.append("enforced_requires_host_effect_confirmation")
    return not errors, errors


def project_operator_state(health: Mapping[str, Any], enforcement: Mapping[str, Any]) -> dict[str, Any]:
    """Project backend truth into labels shared by CLI and dashboards."""
    gate = str(enforcement.get("prevention_gate", "closed")).lower()
    capable = bool(enforcement.get("host_effect_capable", False))
    if gate != "open":
        enforcement_label = "OBSERVE_ONLY"
    elif capable:
        enforcement_label = "ENFORCEMENT_READY"
    else:
        enforcement_label = "ENFORCEMENT_UNAVAILABLE"
    return {
        "runtime": str(health.get("state", "UNKNOWN")),
        "degraded": bool(health.get("degraded", True)),
        "prevention_gate": gate,
        "enforcement_label": enforcement_label,
        "host_effect_capable": capable,
        "confirmed_block_requires_receipt": True,
    }


def incident_from_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize an incident/alert record without inventing enforcement."""
    receipt = record.get("enforcement_receipt")
    receipt_ok = False
    receipt_errors: list[str] = []
    if isinstance(receipt, Mapping):
        receipt_ok, receipt_errors = validate_enforcement_receipt(receipt)
        # A structurally valid pending/simulated receipt is useful evidence,
        # but it is never a confirmed host effect.
        receipt_ok = receipt_ok and str(receipt.get("status", "")).lower() == CONFIRMED_STATUS and bool(receipt.get("host_effect_confirmed", False))
    status = "BLOCKED_CONFIRMED" if receipt_ok else str(record.get("status", "OBSERVED")).upper()
    return {
        "incident_id": record.get("incident_id", record.get("event_id", 0)),
        "event_id": record.get("event_id", 0),
        "rule_id": record.get("rule_id", 0),
        "severity": record.get("severity", "UNKNOWN"),
        "source": record.get("source", "unknown"),
        "src_ip": record.get("src_ip"),
        "dst_ip": record.get("dst_ip"),
        "timestamp_ms": record.get("timestamp_ms", record.get("ts_ms", 0)),
        "status": status,
        "receipt_valid": receipt_ok,
        "receipt_errors": receipt_errors,
        "evidence": record.get("evidence", record.get("reason", "")),
    }


__all__ = [
    "POLICY_ACTION_ORDINALS",
    "PEP_DECISION_ORDINALS",
    "validate_enforcement_receipt",
    "project_operator_state",
    "incident_from_record",
]
