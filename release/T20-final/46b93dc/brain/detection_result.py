"""Validated Python-side DetectionResult adapter.

This module mirrors ``src/detection/detection_result.zig`` at the detection
boundary. It is deliberately limited to detector output: it does not evaluate
policy, call the C++ bridge, invoke Rust PEP, or perform host enforcement.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


DETECTOR_SIGNATURE = 1
DETECTOR_ANOMALY = 2
DETECTOR_CORRELATION = 3
DETECTOR_THREAT_TRACKER = 4

SCAN_MATCH = "MATCH"
SCAN_NO_MATCH = "NO_MATCH"
SCAN_UNKNOWN = "UNKNOWN"
SCAN_ERROR = "ERROR"
SCAN_UNAVAILABLE = "UNAVAILABLE"
SCAN_STATUSES = {
    SCAN_MATCH,
    SCAN_NO_MATCH,
    SCAN_UNKNOWN,
    SCAN_ERROR,
    SCAN_UNAVAILABLE,
}


@dataclass(frozen=True)
class DetectionResult:
    event_id: int
    detector: int = DETECTOR_SIGNATURE
    detector_version: int = 1
    matched: bool = False
    rule_id: int = 0
    incident_id: int = 0
    severity: int = 0
    reason: str = ""
    scan_status: str = SCAN_NO_MATCH

    def validate(self) -> None:
        if self.event_id <= 0:
            raise ValueError("event_id must be positive")
        if self.detector not in {
            DETECTOR_SIGNATURE,
            DETECTOR_ANOMALY,
            DETECTOR_CORRELATION,
            DETECTOR_THREAT_TRACKER,
        }:
            raise ValueError("unknown detector kind")
        if self.detector_version <= 0:
            raise ValueError("detector_version must be positive")
        if not 0 <= self.severity <= 3:
            raise ValueError("severity must be in range 0..3")
        if self.matched and not self.reason:
            raise ValueError("matched detection requires a reason")
        if self.rule_id < 0 or self.incident_id < 0:
            raise ValueError("identifiers cannot be negative")
        if self.scan_status not in SCAN_STATUSES:
            raise ValueError("unknown scan status")
        if self.matched and self.scan_status != SCAN_MATCH:
            raise ValueError("matched detection must have MATCH scan status")
        if not self.matched and self.scan_status == SCAN_MATCH:
            raise ValueError("unmatched detection cannot have MATCH scan status")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)

    @classmethod
    def from_regex_match(
        cls,
        event_id: int,
        match: tuple[str, str, str, int] | None,
        *,
        detector_version: int = 1,
    ) -> "DetectionResult":
        """Convert the canonical ``run_regex_scan`` tuple into a result.

        The tuple is ``(rule_name, policy, rule_id, severity)``. Policy is
        intentionally not copied into this object; action selection belongs to
        the Zig policy layer.
        """
        if match is None:
            result = cls(
                event_id=event_id,
                detector=DETECTOR_SIGNATURE,
                detector_version=detector_version,
                matched=False,
                reason="no_match",
                scan_status=SCAN_NO_MATCH,
            )
            result.validate()
            return result

        rule_name, _policy, rule_id_text, severity = match
        try:
            rule_id = int(rule_id_text)
        except (TypeError, ValueError):
            rule_id = 0
        result = cls(
            event_id=event_id,
            detector=DETECTOR_SIGNATURE,
            detector_version=detector_version,
            matched=True,
            rule_id=rule_id,
            severity=int(severity),
            reason=f"signature_match:{rule_name}",
            scan_status=SCAN_MATCH,
        )
        result.validate()
        return result
