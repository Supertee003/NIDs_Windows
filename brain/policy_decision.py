"""Alert-only policy adapter for the Python detection boundary.

Detection output is advisory. The adapter deliberately does not copy an action
from a Python/Cython rule into a privileged decision. Production policy
selection remains owned by the Zig PolicyEngine; this module is the safe
integration fixture for Phase 5 and emits only ALERT or ALLOW.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .detection_result import DetectionResult


ACTION_ALLOW = "ALLOW"
ACTION_ALERT = "ALERT"


@dataclass(frozen=True)
class PolicyDecision:
    event_id: int
    action: str
    policy_id: int = 0
    detection_rule_id: int = 0
    severity: int = 0
    reason: str = ""
    enforcement_requested: bool = False
    mode: str = "alert_only"

    def validate(self) -> None:
        if self.event_id <= 0:
            raise ValueError("event_id must be positive")
        if self.action not in {ACTION_ALLOW, ACTION_ALERT}:
            raise ValueError("alert-only adapter cannot emit privileged actions")
        if self.policy_id < 0 or self.detection_rule_id < 0:
            raise ValueError("identifiers cannot be negative")
        if not 0 <= self.severity <= 3:
            raise ValueError("severity must be in range 0..3")
        if self.enforcement_requested:
            raise ValueError("alert-only decision cannot request enforcement")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


def decide_alert_only(result: DetectionResult) -> PolicyDecision:
    """Map detection to a non-privileged decision.

    The result is validated first. A match becomes ALERT, while a non-match
    becomes ALLOW. No Python/Cython policy action is trusted as authority.
    """
    result.validate()
    if result.matched:
        decision = PolicyDecision(
            event_id=result.event_id,
            action=ACTION_ALERT,
            detection_rule_id=result.rule_id,
            severity=result.severity,
            reason=result.reason,
        )
    else:
        decision = PolicyDecision(
            event_id=result.event_id,
            action=ACTION_ALLOW,
            detection_rule_id=0,
            severity=0,
            reason=result.reason or "no_match",
        )
    decision.validate()
    return decision
