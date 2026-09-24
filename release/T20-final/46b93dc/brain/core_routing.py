"""Core-facing orchestration seam for detection and Tier-3 routing."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .detection_result import DetectionResult
from .tier_routing import TierRoute, route_detection


@dataclass(frozen=True)
class Tier3Request:
    event_id: int
    reason: str
    detection: DetectionResult

    def validate(self) -> None:
        self.detection.validate()
        if self.event_id != self.detection.event_id:
            raise ValueError("Tier-3 request event identity mismatch")
        if not self.reason:
            raise ValueError("Tier-3 request reason is required")


@dataclass(frozen=True)
class CoreRoutingDecision:
    detection: DetectionResult
    route: TierRoute
    tier3_request: Tier3Request | None = None

    def validate(self) -> None:
        self.detection.validate()
        self.route.validate()
        if self.route.route == "TIER3":
            if self.tier3_request is None:
                raise ValueError("Tier-3 route requires a request")
            self.tier3_request.validate()
        elif self.tier3_request is not None:
            raise ValueError("non-Tier-3 route cannot carry a Tier-3 request")


def route_core_detection(
    detection: DetectionResult,
    *,
    tier3_available: bool,
) -> CoreRoutingDecision:
    """Route a validated result; never creates a policy/enforcement action."""
    route = route_detection(detection, tier3_available=tier3_available)
    request = None
    if route.route == "TIER3":
        request = Tier3Request(
            event_id=detection.event_id,
            reason=route.reason,
            detection=detection,
        )
    decision = CoreRoutingDecision(detection=detection, route=route, tier3_request=request)
    decision.validate()
    return decision
