"""Receipt-first enforcement pipeline seam for Phase 5–7."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .forensic_evidence import ForensicEvidence, evidence_from_receipt
from .pep_receipt import receipt_from_pep_response
from .pep_request import PepRequest


@dataclass(frozen=True)
class MouthState:
    status: str
    label: str
    host_effect_confirmed: bool
    event_id: int
    audit_id: int

    def validate(self) -> None:
        if self.status == "ENFORCED":
            if not self.host_effect_confirmed or self.label != "BLOCKED":
                raise ValueError("ENFORCED Mouth state requires confirmed BLOCKED label")
        elif self.host_effect_confirmed:
            raise ValueError("non-ENFORCED Mouth state cannot confirm host effect")


def mouth_state_from_evidence(evidence: ForensicEvidence) -> MouthState:
    evidence.validate()
    if evidence.receipt_status == "ENFORCED" and evidence.host_effect_confirmed:
        state = MouthState("ENFORCED", "BLOCKED", True, evidence.event_id, evidence.audit_id)
    elif evidence.receipt_status == "UNAVAILABLE":
        state = MouthState("UNAVAILABLE", "PROVIDER_UNAVAILABLE", False, evidence.event_id, evidence.audit_id)
    elif evidence.receipt_status == "FAILED":
        state = MouthState("FAILED", "ENFORCEMENT_FAILED", False, evidence.event_id, evidence.audit_id)
    else:
        state = MouthState(evidence.receipt_status, "OBSERVE", False, evidence.event_id, evidence.audit_id)
    state.validate()
    return state


def process_pep_response(
    request: PepRequest,
    response: Mapping[str, Any],
    *,
    provider: str = "rust_pep",
    filter_id: int = 0,
    host_effect_confirmed: bool = False,
) -> tuple[Any, ForensicEvidence, MouthState]:
    """Convert one identity-bound PEP response into receipt/evidence/display."""
    request.validate()
    receipt = receipt_from_pep_response(
        response,
        request_id=request.request_id,
        event_id=request.event_id,
        policy_id=request.policy_id,
        trace_id=request.trace_id,
        audit_id=request.audit_id,
        provider=provider,
        filter_id=filter_id,
        host_effect_confirmed=host_effect_confirmed,
    )
    evidence = evidence_from_receipt(receipt)
    mouth = mouth_state_from_evidence(evidence)
    return receipt, evidence, mouth
