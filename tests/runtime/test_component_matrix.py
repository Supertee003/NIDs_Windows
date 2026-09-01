"""
test_component_matrix.py - Verify the COMPONENTS table in tests matches
the documented matrix in docs/runtime/COMPONENT_MATRIX.md.

This is a "documentation drift" test: if someone adds a component to the
docs but forgets to update the test fixtures (or vice versa), this test
will fail.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from tests.runtime.conftest import COMPONENTS

# Path to the canonical matrix document.
REPO_ROOT = Path(__file__).resolve().parents[2]
MATRIX_DOC = REPO_ROOT / "docs" / "runtime" / "COMPONENT_MATRIX.md"


def _strip_backticks(s: str) -> str:
    s = s.strip()
    if s.startswith("`") and s.endswith("`") and len(s) >= 2:
        return s[1:-1]
    return s


def _parse_markdown_table(text: str) -> list[dict[str, str]]:
    r"""Naive parser for the primary-engine table in COMPONENT_MATRIX.md
    §2.1. Returns one dict per row keyed by the lower-cased column name.
    Strips backticks around cell values so `bridge` (with backticks) becomes
    `bridge` (without)."""
    rows: list[dict[str, str]] = []
    in_table = False
    headers: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            in_table = False
            continue
        cells = [_strip_backticks(c.strip()) for c in line.strip("|").split("|")]
        if not in_table:
            # First row is the header.
            headers = [c.lower() for c in cells]
            in_table = True
            continue
        # Second row is the separator (---|---|...). Skip it.
        if all(re.fullmatch(r":?-{3,}:?", c) for c in cells):
            continue
        rows.append(dict(zip(headers, cells)))
    return rows


class TestMatrixDocExists(unittest.TestCase):

    def test_matrix_doc_present(self):
        self.assertTrue(MATRIX_DOC.exists(),
                        f"missing {MATRIX_DOC}; runbook depends on it")


class TestMatrixDocHasExpectedTables(unittest.TestCase):

    def setUp(self):
        if not MATRIX_DOC.exists():
            self.skipTest("matrix doc not present")
        self.text = MATRIX_DOC.read_text(encoding="utf-8")

    def test_has_primary_engines_section(self):
        self.assertIn("### 2.1 Primary engines", self.text)

    def test_has_kernel_drivers_section(self):
        self.assertIn("### 2.2 Kernel drivers", self.text)

    def test_has_auxiliary_services_section(self):
        self.assertIn("### 2.3 Auxiliary services", self.text)

    def test_has_startup_order_section(self):
        self.assertIn("## 4. Startup order", self.text)

    def test_has_shutdown_order_section(self):
        self.assertIn("## 5. Shutdown order", self.text)

    def test_has_failure_mode_matrix(self):
        self.assertIn("## 6. Failure-mode matrix", self.text)


class TestPrimaryEngineRowsMatchFixture(unittest.TestCase):
    """Every primary-engine row in the markdown matrix should be present
    in the COMPONENTS fixture (and vice versa). This catches drift
    between docs and test data."""

    def setUp(self):
        if not MATRIX_DOC.exists():
            self.skipTest("matrix doc not present")
        text = MATRIX_DOC.read_text(encoding="utf-8")
        # Slice out just §2.1 to keep the parser simple.
        section = text.split("### 2.1", 1)[1]
        section = section.split("### 2.2", 1)[0]
        self.rows = _parse_markdown_table(section)

    def test_doc_includes_all_fixture_components(self):
        fixture_names = {c["name"] for c in COMPONENTS}
        doc_names = {r.get("component", "").lower() for r in self.rows}
        # Allow `core` vs `Core` etc. (case-insensitive compare).
        for name in fixture_names:
            self.assertTrue(
                any(n.lower() == name for n in doc_names),
                f"component {name!r} in fixture but not in COMPONENT_MATRIX.md §2.1"
            )

    def test_fixture_includes_all_doc_components(self):
        fixture_names = {c["name"].lower() for c in COMPONENTS}
        for row in self.rows:
            name = row.get("component", "").lower()
            if not name:
                continue
            self.assertIn(name, fixture_names,
                          f"component {name!r} in doc but not in fixture")


class TestStartupOrderDocumented(unittest.TestCase):

    def setUp(self):
        if not MATRIX_DOC.exists():
            self.skipTest("matrix doc not present")
        self.text = MATRIX_DOC.read_text(encoding="utf-8")

    def test_bridge_is_first_in_startup_order(self):
        # The numbered list in §4 must list `bridge` first.
        section = self.text.split("## 4. Startup order", 1)[1]
        section = section.split("## 5.", 1)[0]
        # Extract the first numbered item.
        match = re.search(r"^\s*1\.\s+`(\w+)`", section, re.MULTILINE)
        self.assertIsNotNone(match, "could not find first startup step")
        self.assertEqual(match.group(1), "bridge")

    def test_bridge_is_last_in_shutdown_order(self):
        section = self.text.split("## 5. Shutdown order", 1)[1]
        section = section.split("## 6.", 1)[0]
        # Find the line that mentions `bridge` and verify it is the
        # last numbered item that mentions a primary engine.
        lines = [
            re.search(r"`(\w+)`", line).group(1)
            for line in section.splitlines()
            if re.match(r"^\s*\d+\.\s+`(\w+)`", line)
        ]
        self.assertTrue(lines, "no shutdown steps found")
        self.assertEqual(lines[-1], "bridge")


class TestFailureModeMatrixDocumented(unittest.TestCase):

    def setUp(self):
        if not MATRIX_DOC.exists():
            self.skipTest("matrix doc not present")
        self.text = MATRIX_DOC.read_text(encoding="utf-8")

    def test_required_components_marked_yes(self):
        section = self.text.split("## 6. Failure-mode matrix", 1)[1]
        # `bridge` row must say Required = yes.
        for line in section.splitlines():
            if "bridge" in line and "yes" in line.lower():
                return
        self.fail("bridge should be Required=yes in failure-mode matrix")

    def test_optional_components_marked_no(self):
        section = self.text.split("## 6. Failure-mode matrix", 1)[1]
        for name in ("nose", "mouth", "aggregator"):
            found = False
            for line in section.splitlines():
                if name in line and "no" in line.lower():
                    found = True
                    break
            self.assertTrue(found,
                            f"{name} should be Required=no in failure-mode matrix")


if __name__ == "__main__":
    unittest.main()
