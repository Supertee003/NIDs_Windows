"""P5-DETECTION-TRUTH pins: doc parity for detection coverage and provenance.

Records-only E1 guards. They stop the retired "23/23 evaluable", the false MITRE
"only occurrence" claim, the unwired ML diagram input and the seven-language
count from returning. Frozen release snapshots under release/ are untouched.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def test_catalog_separates_code_path_from_host_evaluable_coverage() -> None:
    text = _read("docs/portfolio/DETECTION_CATALOG.md")
    assert "**Code-path coverage**" in text
    assert "**Host-evaluable coverage**" in text
    assert "**22/23** — R2003 blocked by FN-1" in text
    assert "| **Evaluable coverage**" not in text


def test_catalog_mitre_statement_names_the_real_occurrences() -> None:
    text = _read("docs/portfolio/DETECTION_CATALOG.md")
    assert "the only occurrence is an ATS keyword" not in text
    assert "NOT-WIRED injection detector" in text
    assert "test-only scenario library" in text


def test_catalog_and_validation_carry_current_source_provenance() -> None:
    catalog = _read("docs/portfolio/DETECTION_CATALOG.md")
    validation = _read("docs/DETECTION_VALIDATION.md")
    for text in (catalog, validation):
        assert "661fb76" in text
        assert "been re-measured" in text
        assert "HISTORICAL" in text


def test_architecture_marks_ml_unwired_and_paths_as_historical() -> None:
    text = _read("docs/ARCHITECTURE.md")
    assert "ML flow detector (NOT WIRED - test/CLI only)" in text
    assert "Path convention (P5-DETECTION-TRUTH)" in text
    assert "There is no `core/` directory in this tree" in text


def test_ai_context_uses_the_canonical_language_count() -> None:
    text = _read("AI_CONTEXT.md")
    assert "seven-language architecture" not in text
    assert "six language families (seven toolchains; TypeScript advisory-only" in text


def test_golden_path_generator_marks_itself_declaration_only() -> None:
    text = _read("tools/golden_path_evidence.py")
    assert "HISTORICAL T20 Golden Path declaration package" in text
    assert 'ev["declaration_only"] = True' in text
    assert "declaration, not end-to-end verification" in text


def test_rule_coverage_matrix_scopes_its_historical_board() -> None:
    text = _read("analysis/current-head/RULE-COVERAGE-001-MATRIX.md")
    assert "HISTORICAL @ recorded head" in text
    assert "host-evaluable 22/23" in text
    assert "Board stays 5/6." not in text
