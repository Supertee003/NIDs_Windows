"""Typed, policy-authority-bound request adapter for Rust Shield/PEP."""
from __future__ import annotations

from dataclasses import dataclass

from .core_routing import CoreRoutingDecision
from .detection_result import DetectionResult

ACTION_ALERT = 1
ACTION_LOG = 2
ACTION_BLOCK = 3
ACTION_ESCALATE = 4


@dataclass(frozen=True)
class PepRequest:
    request_id: int
    event_id: int
    policy_id: int
    trace_id: int
    audit_id: int
    requested_action: int
    severity: int
    caller_capability_mask: int
    reason: str

    def validate(self) -> None:
        if min(self.request_id, self.event_id, self.trace_id, self.audit_id) <= 0:
            raise ValueError("PEP identity values must be positive")
        if self.policy_id < 0 or self.severity < 0 or self.caller_capability_mask < 0:
            raise ValueError("PEP numeric fields cannot be negative")
        if self.requested_action not in {ACTION_ALERT, ACTION_LOG, ACTION_BLOCK, ACTION_ESCALATE}:
            raise ValueError("unknown PEP action")
        if not self.reason:
            raise ValueError("PEP reason is required")


def pep_request_from_routing(
    routing: CoreRoutingDecision,
    *,
    request_id: int,
    trace_id: int,
    audit_id: int,
    policy_id: int,
    caller_capability_mask: int = 0,
    requested_action: int = ACTION_ALERT,
) -> PepRequest | None:
    """Create a PEP request only for a policy route.

    Detection and Tier-3 routes never become enforcement requests. Rust Shield
    remains the authority that evaluates this request and returns the result.
    """
    routing.validate()
    if routing.route.route != "POLICY":
        return None
    detection: DetectionResult = routing.detection
    request = PepRequest(
        request_id=request_id,
        event_id=detection.event_id,
        policy_id=policy_id,
        trace_id=trace_id,
        audit_id=audit_id,
        requested_action=requested_action,
        severity=detection.severity,
        caller_capability_mask=caller_capability_mask,
        reason=detection.reason,
    )
    request.validate()
    return request
