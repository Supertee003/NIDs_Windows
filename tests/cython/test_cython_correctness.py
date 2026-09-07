"""T5b correctness: Cython scan_cython and pure-Python scan_cython return
the same result for every payload in a representative test corpus.

The Cython path must be semantically equivalent to the pure-Python
fallback. This test is the cross-check between the two implementations.

If this test ever fails:
  - The Cython and Python implementations have drifted. Re-derive one
    from the other.
  - The test corpus has caught a payload whose match is order-dependent
    (the first match in one impl is not the first in the other). The
    fix is to make the order in the engine deterministic.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from brain.cython import build_engine, is_cython_available, scan_cython  # noqa: E402
from brain.windows_brain import load_rules  # noqa: E402

PAYLOADS: list[tuple[str, str]] = [
    # (label, payload)
    ("sql_injection", "GET /x?a=UNION SELECT 1 HTTP/1.1"),
    ("xss", "<script>alert(1)</script>"),
    ("path_traversal", "../../../etc/passwd"),
    ("os_command", "user; ls -la"),
    ("benign", "GET /index.html HTTP/1.1\r\nHost: example.com\r\n"),
    ("empty", ""),
    ("no_match_in_rules", "completely benign text without any rule patterns"),
    ("mixed", "POST /login\r\nXSS: <script>foo</script> UNION SELECT x"),
]


@pytest.fixture(scope="module")
def engine():
    rules = load_rules()
    return build_engine(rules)


@pytest.mark.skipif(
    not is_cython_available(),
    reason="Cython extension not compiled; only Python fallback is available",
)
@pytest.mark.parametrize("label,payload", PAYLOADS)
def test_cython_and_python_fallback_agree(label: str, payload: str, engine) -> None:
    """The Cython path and the pure-Python path must return the same result.

    For each payload, we import the fallback directly and compare the
    Cython path's return value to the fallback's return value.
    """
    from brain.cython import _py_fallback as py_fb

    cy_result = scan_cython(payload, engine)
    py_result = py_fb.scan_cython(payload, engine)

    assert cy_result == py_result, (
        f"[{label}] Cython and Python fallback disagree:\n"
        f"  payload: {payload!r}\n"
        f"  cython : {cy_result!r}\n"
        f"  python : {py_result!r}"
    )


def test_fallback_returns_match_tuple_shape() -> None:
    """When a match is found, the tuple must be (name, policy, rule_id, severity, index)."""
    rules = {
        "nids_rules": [
            {
                "name": "Test",
                "rule_id": "R-TEST",
                "regex_pattern": r"foo",
                "action": "Block",
                "severity": "High",
            }
        ]
    }
    engine = build_engine(rules)
    result = scan_cython("foobar", engine)
    assert result is not None
    name, policy, rule_id, severity, index = result
    assert name == b"Test"
    assert policy == b"BLOCK"
    assert rule_id == b"R-TEST"
    assert severity == 2  # High
    assert index == 0


def test_fallback_returns_none_when_no_match() -> None:
    rules = {
        "nids_rules": [
            {
                "name": "Test",
                "rule_id": "R-TEST",
                "regex_pattern": r"foo",
                "action": "Block",
                "severity": "High",
            }
        ]
    }
    engine = build_engine(rules)
    result = scan_cython("bar baz", engine)
    assert result is None


def test_fallback_skips_rules_with_no_compilable_pattern() -> None:
    """Rules with neither regex_pattern nor match_pattern are skipped (return None)."""
    rules = {
        "nids_rules": [
            {"name": "No pattern", "rule_id": "R-X"},
            {"name": "Has pattern", "rule_id": "R-Y", "regex_pattern": r"hello"},
        ]
    }
    engine = build_engine(rules)
    result = scan_cython("hello world", engine)
    assert result is not None
    _, _, rule_id, _, index = result
    assert rule_id == b"R-Y"
    assert index == 1


def test_fallback_severity_default_is_medium() -> None:
    """Missing severity falls back to Medium (1)."""
    rules = {
        "nids_rules": [
            {"name": "NoSev", "rule_id": "R-Z", "regex_pattern": r"x"},
        ]
    }
    engine = build_engine(rules)
    result = scan_cython("xxx", engine)
    assert result is not None
    _, _, _, severity, _ = result
    assert severity == 1
