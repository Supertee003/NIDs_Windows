"""Rust Shield/PEP response to EnforcementReceipt mapping.

This module is deliberately transport-neutral. It consumes the already
validated PEP result and produces evidence; it does not call WFP or infer a
host effect from a requested decision.
"""
from __future__ import annotations

from typing import Any, Mapping

from .enforcement_receipt import (
    STATUS_ENFORCED,
    STATUS_FAILED,
    STATUS_SIMULATED,
    STATUS_UNAVAILABLE,
    EnforcementReceipt,
)


PEP_ALLOW = 0
PEP_BLOCK = 1
PEP_RATE_LIMIT = 2
PEP_QUARANTINE = 3
PEP_ESCALATE = 4
PEP_DROP = 5

REASON_WFP_UNAVAILABLE = 4


def receipt_from_pep_response(
    response: Mapping[str, Any],
    *,
    request_id: int,
    event_id: int,
    policy_id: int,
    trace_id: int,
    audit_id: int,
    provider: str = "rust_pep",
    filter_id: int = 0,
    host_effect_confirmed: bool = False,
) -> EnforcementReceipt:
    """Map a Rust PEP response to a receipt without upgrading evidence.

    BLOCK is ENFORCED only when the provider and host explicitly confirm the
    effect. PEP ESCALATE reason 4 is the known WFP-unavailable path and is
    represented as UNAVAILABLE, never as ALLOW or ENFORCED.
    """
    decision = int(response.get("decision", PEP_ESCALATE))
    reason_code = int(response.get("reason", 0) or 0)

    if decision == PEP_BLOCK and host_effect_confirmed and filter_id > 0:
        status = STATUS_ENFORCED
        reason = "pep_block_host_effect_confirmed"
    elif decision == PEP_ESCALATE and reason_code == REASON_WFP_UNAVAILABLE:
        status = STATUS_UNAVAILABLE
        reason = "wfp_provider_unavailable"
        host_effect_confirmed = False
        filter_id = 0
    elif decision == PEP_ALLOW:
        status = STATUS_SIMULATED
        reason = "pep_allow_no_host_effect"
        host_effect_confirmed = False
        filter_id = 0
    elif decision in {PEP_BLOCK, PEP_RATE_LIMIT, PEP_QUARANTINE, PEP_DROP}:
        status = STATUS_FAILED
        reason = "pep_decision_without_host_effect_proof"
        host_effect_confirmed = False
        filter_id = 0
    else:
        status = STATUS_FAILED
        reason = "pep_escalated_without_provider_proof"
        host_effect_confirmed = False
        filter_id = 0

    mode = "enforced" if status == STATUS_ENFORCED else "alert_only"

    receipt = EnforcementReceipt(
        request_id=request_id,
        event_id=event_id,
        policy_id=policy_id,
        decision=decision,
        status=status,
        provider=provider,
        filter_id=filter_id,
        host_effect_confirmed=host_effect_confirmed,
        reason=reason,
        trace_id=trace_id,
        audit_id=audit_id,
        mode=mode,
    )
    receipt.validate()
    return receipt
