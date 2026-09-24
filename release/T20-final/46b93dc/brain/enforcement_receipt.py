"""Versioned alert-only EnforcementReceipt boundary.

This adapter mirrors the essential fields of the Zig receipt contract while
keeping alert-only execution explicit. It never claims a host effect and never
calls PEP, C++, WFP, or a subprocess.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .policy_decision import PolicyDecision


RECEIPT_VERSION = 1
STATUS_SIMULATED = "SIMULATED"
STATUS_UNAVAILABLE = "UNAVAILABLE"
STATUS_FAILED = "FAILED"
STATUS_ENFORCED = "ENFORCED"


@dataclass(frozen=True)
class EnforcementReceipt:
    request_id: int
    event_id: int
    policy_id: int
    decision: str
    status: str
    provider: str
    filter_id: int = 0
    host_effect_confirmed: bool = False
    reason: str = ""
    receipt_version: int = RECEIPT_VERSION
    mode: str = "alert_only"
    trace_id: int = 0
    audit_id: int = 0

    def validate(self) -> None:
        if self.receipt_version != RECEIPT_VERSION:
            raise ValueError("unsupported receipt version")
        if self.request_id <= 0 or self.event_id <= 0:
            raise ValueError("receipt identity must be positive")
        if self.policy_id < 0 or self.filter_id < 0:
            raise ValueError("receipt identifiers cannot be negative")
        if not self.provider:
            raise ValueError("receipt provider is required")
        if self.status == STATUS_ENFORCED and not self.host_effect_confirmed:
            raise ValueError("ENFORCED requires host-effect confirmation")
        if self.mode == "alert_only" and self.host_effect_confirmed:
            raise ValueError("alert-only receipt cannot confirm host effect")
        if self.status in {STATUS_SIMULATED, STATUS_UNAVAILABLE, STATUS_FAILED} and self.host_effect_confirmed:
            raise ValueError("non-enforced receipt cannot confirm host effect")

    def is_forensically_linkable(self) -> bool:
        self.validate()
        return self.trace_id > 0 and self.audit_id > 0

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


def receipt_from_alert_decision(
    decision: PolicyDecision,
    *,
    request_id: int,
    reason: str = "alert_only_no_host_effect",
) -> EnforcementReceipt:
    """Create a non-privileged receipt from an alert-only decision."""
    decision.validate()
    if decision.action not in {"ALLOW", "ALERT"}:
        raise ValueError("only ALLOW/ALERT decisions may enter alert-only receipt")
    receipt = EnforcementReceipt(
        request_id=request_id,
        event_id=decision.event_id,
        policy_id=decision.policy_id,
        decision=decision.action,
        status=STATUS_SIMULATED,
        provider="none",
        reason=reason,
        trace_id=decision.event_id,
        audit_id=request_id,
    )
    receipt.validate()
    return receipt
