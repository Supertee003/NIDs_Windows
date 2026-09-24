"""Unified policy-neutral result adapter for Python/Cython scanning."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .detection_result import (
    SCAN_ERROR,
    SCAN_MATCH,
    SCAN_NO_MATCH,
    SCAN_UNAVAILABLE,
    SCAN_UNKNOWN,
    DetectionResult,
)


def result_from_scan(
    event_id: int,
    match: tuple[Any, ...] | None,
    *,
    scan_status: str | None = None,
    error: str = "",
) -> DetectionResult:
    """Normalize the canonical 4/5-field scanner result.

    The scanner may be Python fallback or Cython fast-path. Neither path may
    provide policy authority; only detection metadata is copied.
    """
    if error:
        result = DetectionResult(event_id=event_id, reason=error, scan_status=SCAN_ERROR)
        result.validate()
        return result
    if scan_status == SCAN_UNAVAILABLE:
        result = DetectionResult(event_id=event_id, reason="scanner_unavailable", scan_status=SCAN_UNAVAILABLE)
        result.validate()
        return result
    if scan_status == SCAN_UNKNOWN:
        result = DetectionResult(event_id=event_id, reason="scanner_unknown", scan_status=SCAN_UNKNOWN)
        result.validate()
        return result
    if match is None:
        return DetectionResult.from_regex_match(event_id, None)
    if len(match) < 4:
        result = DetectionResult(event_id=event_id, reason="malformed_scan_result", scan_status=SCAN_ERROR)
        result.validate()
        return result
    normalized = list(match[:4])
    for index in (0, 1, 2):
        if isinstance(normalized[index], bytes):
            normalized[index] = normalized[index].decode("utf-8", errors="replace")
    return DetectionResult.from_regex_match(event_id, tuple(normalized))


def scan_to_detection_result(
    event_id: int,
    payload: str,
    rules_data: Mapping[str, Any],
    tier2_engine: Mapping[str, Any],
    scanner: Callable[[str, Mapping[str, Any], Mapping[str, Any]], tuple[Any, ...] | None],
) -> DetectionResult:
    """Run either canonical scanner implementation and normalize its output."""
    try:
        return result_from_scan(
            event_id,
            scanner(payload, tier2_engine, rules_data),
        )
    except (ImportError, ModuleNotFoundError):
        return result_from_scan(event_id, None, scan_status=SCAN_UNAVAILABLE)
    except Exception as exc:  # scanner errors become data, never policy
        return result_from_scan(event_id, None, error=f"scanner_error:{type(exc).__name__}")
