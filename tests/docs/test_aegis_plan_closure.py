"""AEGIS-PLAN 007-020 closure pins (2026-11-26).

Records-only E1 guards for the documentation deliverables that closed the
scoped 20-item plan. These tests assert that an honest status page still says
what it proved and what it did not. They do not run builds, host proofs, or
any elevated operation.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

DOCS = {
    "AEGIS-007-QUEUE": "docs/runtime/QUEUE_SEMANTICS.md",
    "AEGIS-008-SENSOR": "docs/portfolio/SENSOR_COVERAGE.md",
    "AEGIS-009-KERNEL": "docs/runtime/KERNEL_LIFECYCLE.md",
    "AEGIS-011-FORENSIC": "docs/forensics/FORENSIC_CHAIN_STATUS.md",
    "AEGIS-012-PERFORMANCE": "docs/portfolio/PERFORMANCE_REPORT.md",
    "AEGIS-013-VERIFICATION": "docs/portfolio/VERIFICATION_SUMMARY.md",
    "AEGIS-015-DOCS": "docs/DOCS_LIFECYCLE.md",
    "AEGIS-017-FUZZ": "docs/testing/FAULT_INJECTION_INVENTORY.md",
    "AEGIS-018-CI": "docs/CI_QUALITY_GATES.md",
    "AEGIS-019-COMPAT": "docs/DEPLOYMENT_COMPATIBILITY.md",
    "AEGIS-020-CASE": "docs/portfolio/CASE_STUDY.md",
}


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def test_all_closure_docs_exist_and_name_build_source() -> None:
    for label, rel in DOCS.items():
        text = _read(rel)
        assert "4dd3393" in text, label
        assert len(text.splitlines()) >= 30, label


def test_queue_doc_keeps_drop_and_backpressure_distinct() -> None:
    text = _read(DOCS["AEGIS-007-QUEUE"])
    assert "queue_dropped_total" in text
    assert "Blocking-producer backpressure" in text
    assert "not implemented" in text
    assert "Silent loss" in text


def test_sensor_doc_keeps_measured_and_source_support_separate() -> None:
    text = _read(DOCS["AEGIS-008-SENSOR"])
    assert "Measured proof" in text
    assert "Source-level support" in text
    assert "NOT_PROVEN" in text


def test_kernel_doc_does_not_claim_a_load() -> None:
    text = _read(DOCS["AEGIS-009-KERNEL"])
    assert "NOT_PROVEN" in text
    assert "no kernel object was" in text
    assert "OWNER-RUN-HOST-PROOF-RUNBOOK-20261126.md" in text


def test_forensic_doc_names_the_full_chain() -> None:
    text = _read(DOCS["AEGIS-011-FORENSIC"])
    for stage in ("Event", "forensic record", "CRC", "persistence", "verify", "replay", "audit"):
        assert stage in text, stage
    assert "HISTORICAL" in text


def test_performance_doc_does_not_claim_a_benchmark() -> None:
    text = _read(DOCS["AEGIS-012-PERFORMANCE"])
    assert "NOT RUN" in text
    assert "not a controlled benchmark" in text
    assert "NOT CLAIMED" in text


def test_ci_doc_records_real_workflow_paths() -> None:
    text = _read(DOCS["AEGIS-018-CI"])
    assert ".github/workflows/ci.yml" in text
    assert ".github/workflows/host-regression.yml" in text
    assert "ci_coverage.json" in text
    assert "E4 PASS" in text


def test_compatibility_doc_has_no_fake_pass_rows() -> None:
    text = _read(DOCS["AEGIS-019-COMPAT"])
    assert "NOT_TESTED" in text
    assert "A declare-only row is not a PASS row" in text
    assert "Windows Server 2022" in text


def test_case_study_lists_real_limits() -> None:
    text = _read(DOCS["AEGIS-020-CASE"])
    assert "No current-head full Windows E5" in text
    assert "No controlled fixed-rate throughput ceiling" in text
    assert "6/6 gates PASS at that identity only" in text


def test_host_live_diagnosis_names_stale_binary_and_no_fake_pass() -> None:
    text = _read("docs/testing/HOST_LIVE_DIAGNOSIS.md")
    assert "FBD9BDB3456C9C7DAFCBF1B0C3FBDAD9778F61C3186167856E373CC376185474" in text
    assert "a53eda8" in text
    assert "AEGIS_NOSE_IFACE" in text
    assert "Not established" in text
    assert "no test was relaxed" in text


def test_runbook_requires_loopback_pin_for_e6_tests() -> None:
    text = _read("analysis/current-head/OWNER-RUN-HOST-PROOF-RUNBOOK-20261126.md")
    assert "AEGIS_NOSE_IFACE=\\Device\\NPF_Loopback" in text
    assert "HOST_LIVE_DIAGNOSIS.md" in text


def test_fuzz_inventory_records_the_real_smoke_run() -> None:
    text = _read("docs/testing/FAULT_INJECTION_INVENTORY.md")
    assert "7681B52FC91CC0DE8F8A50143BC98630EB77D666275D6854CFEAE7DEE0B1C621" in text
    assert "0xDEADBEEF" in text
    assert "deterministic E2 fuzz smoke run" in text
    assert "not a coverage-guided campaign" in text


def test_verification_summary_uses_current_build_source() -> None:
    text = _read(DOCS["AEGIS-013-VERIFICATION"])
    assert "4dd33936909de1314099652a7523e52c40bb2c44" in text
    assert "`7822f4c` (HISTORICAL at `4dd3393`)" in text
    assert "45675880854" in text
    assert "1,518 passed" in text
    assert "`4dd3393`" in text


def test_ci_page_records_real_actions_runs_without_e5_claim() -> None:
    text = _read("docs/CI_QUALITY_GATES.md")
    assert "45675880854" in text
    assert "45676093328" in text
    assert "e64ea2500dec840a1c2d9af77bc2b3b3b3385d76" in text
    assert "E4 PASS" in text
    assert "not** E5" in text
    assert "NOT RECORDED IN THIS TREE" not in text


def test_performance_report_records_real_e2_microbenchmark() -> None:
    text = _read(DOCS["AEGIS-012-PERFORMANCE"])
    assert "8829E03D841FF3F4BE12223226EBCD7FDE9313DF8D2F245FFE15703BD182A476" in text
    assert "1a. Zig microbenchmark actually run" in text
    assert "E2 in-process microbenchmark" in text
    assert "not a packet-rate test" in text
    assert "Controlled fixed-rate benchmark at current source | **NOT RUN**" in text


def test_provenance_records_locator_split_and_tool() -> None:
    text = _read("docs/evidence/PROVENANCE.md")
    assert "tools/verify_evidence_locators.py" in text
    for count in ("52", "4", "18", "30"):
        assert count in text
    assert (_read("tools/verify_evidence_locators.py").count("return 0") == 1)
