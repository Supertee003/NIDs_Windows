"""Deterministic routing for policy-neutral DetectionResult values."""
from __future__ import annotations

from dataclasses import dataclass

from .detection_result import (
    SCAN_ERROR,
    SCAN_MATCH,
    SCAN_NO_MATCH,
    SCAN_UNKNOWN,
    SCAN_UNAVAILABLE,
    DetectionResult,
)

ROUTE_POLICY = "POLICY"
ROUTE_COMPLETE = "COMPLETE"
ROUTE_TIER3 = "TIER3"
ROUTE_FAIL_CLOSED = "FAIL_CLOSED"


@dataclass(frozen=True)
class TierRoute:
    route: str
    reason: str
    tier3_required: bool
    tier3_available: bool

    def validate(self) -> None:
        if self.route not in {ROUTE_POLICY, ROUTE_COMPLETE, ROUTE_TIER3, ROUTE_FAIL_CLOSED}:
            raise ValueError("unknown route")
        if self.route == ROUTE_TIER3 and not self.tier3_required:
            raise ValueError("TIER3 route must require Tier-3")
        if self.route == ROUTE_FAIL_CLOSED and self.tier3_available:
            raise ValueError("fail-closed route cannot claim Tier-3 availability")


def route_detection(result: DetectionResult, *, tier3_available: bool) -> TierRoute:
    """Route detection output without selecting an enforcement action."""
    result.validate()
    if result.scan_status == SCAN_MATCH:
        route = TierRoute(ROUTE_POLICY, "tier1_or_tier2_match", False, tier3_available)
    elif result.scan_status == SCAN_NO_MATCH:
        route = TierRoute(ROUTE_COMPLETE, "no_match_complete", False, tier3_available)
    elif result.scan_status in {SCAN_UNKNOWN, SCAN_ERROR, SCAN_UNAVAILABLE}:
        if tier3_available:
            route = TierRoute(ROUTE_TIER3, f"{result.scan_status.lower()}_requires_deep_analysis", True, True)
        else:
            route = TierRoute(ROUTE_FAIL_CLOSED, f"tier3_unavailable_for_{result.scan_status.lower()}", True, False)
    else:  # Defensive; DetectionResult.validate currently closes this set.
        route = TierRoute(ROUTE_FAIL_CLOSED, "unknown_scan_status", True, False)
    route.validate()
    return route
