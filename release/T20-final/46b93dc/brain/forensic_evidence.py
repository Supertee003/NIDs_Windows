"""Receipt-backed forensic evidence envelope.

The envelope is a persistence-neutral representation. It does not write files,
call the Zig ring, or perform enforcement; it validates that evidence fields
are copied from one authoritative EnforcementReceipt without identity drift.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .enforcement_receipt import EnforcementReceipt


@dataclass(frozen=True)
class ForensicEvidence:
    event_id: int
    audit_id: int
    trace_id: int
    policy_id: int
    pep_decision: int
    receipt_status: str
    host_effect_confirmed: bool
    provider: str
    filter_id: int
    receipt_version: int

    def validate(self) -> None:
        if self.event_id <= 0 or self.audit_id <= 0 or self.trace_id <= 0:
            raise ValueError("forensic identity must be positive")
        if self.policy_id < 0 or self.filter_id < 0:
            raise ValueError("forensic identifiers cannot be negative")
        if self.pep_decision < 0:
            raise ValueError("pep decision cannot be negative")
        if not self.provider:
            raise ValueError("forensic provider is required")
        if self.receipt_status == "ENFORCED" and not self.host_effect_confirmed:
            raise ValueError("enforced evidence requires host-effect confirmation")
        if self.host_effect_confirmed and self.receipt_status != "ENFORCED":
            raise ValueError("host effect requires enforced receipt status")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)

    def matches_receipt(self, receipt: EnforcementReceipt) -> bool:
        receipt.validate()
        self.validate()
        return (
            self.event_id == receipt.event_id
            and self.audit_id == receipt.audit_id
            and self.trace_id == receipt.trace_id
            and self.policy_id == receipt.policy_id
            and self.pep_decision == receipt.decision
            and self.receipt_status == receipt.status
            and self.host_effect_confirmed == receipt.host_effect_confirmed
            and self.provider == receipt.provider
            and self.filter_id == receipt.filter_id
            and self.receipt_version == receipt.receipt_version
        )


def evidence_from_receipt(receipt: EnforcementReceipt) -> ForensicEvidence:
    """Create evidence by copying only receipt-authoritative fields."""
    receipt.validate()
    evidence = ForensicEvidence(
        event_id=receipt.event_id,
        audit_id=receipt.audit_id,
        trace_id=receipt.trace_id,
        policy_id=receipt.policy_id,
        pep_decision=receipt.decision,
        receipt_status=receipt.status,
        host_effect_confirmed=receipt.host_effect_confirmed,
        provider=receipt.provider,
        filter_id=receipt.filter_id,
        receipt_version=receipt.receipt_version,
    )
    evidence.validate()
    if not evidence.matches_receipt(receipt):
        raise ValueError("receipt/evidence identity mismatch")
    return evidence
