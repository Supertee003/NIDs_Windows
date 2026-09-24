"""Explicit gates for Phase 8–10; no gate infers readiness from artifacts alone."""
from __future__ import annotations

from typing import Any, Mapping


def lifecycle_gate(before: Mapping[str, Any], after: Mapping[str, Any]) -> bool:
    workers = after.get("workers", {})
    required_workers = (
        "pipeline_ready",
        "sensor_ready",
        "nose_ready",
        "etw_ready",
        "fim_ready",
        "registry_ready",
    )
    workers_ready = all(workers.get(name) is True for name in required_workers)
    return (
        after.get("rust_shield", {}).get("state") == "READY"
        and after.get("rust_shield", {}).get("pep_ready") is True
        and after.get("rust_shield", {}).get("policy_authority") is True
        and after.get("forensic", {}).get("verified") is True
        and after.get("records", 0) >= before.get("records", 0)
        and workers_ready
        and after.get("overall_gate") is not True
    )


def tier3_gate(health: Mapping[str, Any]) -> bool:
    tier3 = health.get("tier3", {})
    return (
        tier3.get("artifact_present") is True
        and tier3.get("dependency_ready") is True
        and tier3.get("provider_ready") is True
        and tier3.get("host_effect_capable") is True
        and tier3.get("ready") is True
    )


def wfp_host_effect_gate(
    health: Mapping[str, Any],
    receipt: Mapping[str, Any],
    postcondition: Mapping[str, Any],
) -> bool:
    shield = health.get("rust_shield", {})
    return (
        shield.get("provider_ready") is True
        and shield.get("host_effect_capable") is True
        and receipt.get("status") == "ENFORCED"
        and receipt.get("host_effect_confirmed") is True
        and postcondition.get("verified") is True
    )
