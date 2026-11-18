"""KIDS-002: production policy handling is assessment-only."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_gate_closed_policy_path_assesses_without_enforcement_or_dispatch():
    source = (ROOT / "src/pipeline/event_processor.zig").read_text(encoding="utf-8")
    start = source.index("if (state.g_prevention_gate_open) {")
    end = source.index("_ = state.g_pipeline_detections", start)
    branch = source[start:end]
    lab_branch, assessment_branch = branch.split("} else {", maxsplit=1)

    assert "pep_enf.enforce(" in lab_branch
    assert "dispatchWithReceipt(" in lab_branch
    assert "pep.assessmentVerdict(pep_enf.assess(" in assessment_branch
    assert "pep_enf.enforce(" not in assessment_branch
    assert "dispatchWithReceipt(" not in assessment_branch


def test_evidence_assessment_does_not_require_initialized_enforcement_provider():
    source = (ROOT / "src/policy/pep_bindings.zig").read_text(encoding="utf-8")
    start = source.index("pub fn assess(")
    end = source.index("pub fn enforce(", start)
    assessment = source[start:end]

    assert "aegis_pep_assess(" in assessment
    assert "self.available" not in assessment
    assert "last_receipt" not in assessment
