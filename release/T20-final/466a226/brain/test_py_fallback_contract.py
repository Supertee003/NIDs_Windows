"""FALLBACK-096: pure-Python scan contract pins.

brain.cython._py_fallback is the correctness oracle AND the runtime
fallback when the Cython extension is not compiled: build_engine must
return the exact five-list shape, and scan_cython must return the first
match as a 5-tuple (name, policy, rule_id, severity, index) or None.
Pure functions, no I/O.
"""
from brain.cython._py_fallback import build_engine, scan_cython


def _rules():
    return {
        "nids_rules": [
            {
                "name": "sqli",
                "rule_id": "R0056",
                "regex_pattern": r"OR '1'='1",
                "action": "Alert",
                "severity": "High",
            },
            {
                "name": "xss",
                "rule_id": "R9059",
                "match_pattern": "script",
                "action": "Block",
                "severity": "Critical",
            },
            {
                "name": "broken",
                "rule_id": "R0000",
                "regex_pattern": "(unclosed",
                "action": "Alert",
                "severity": "Bogus",
            },
        ]
    }


def test_build_engine_shape_and_parallel_lengths():
    eng = build_engine(_rules())
    assert set(eng.keys()) == {"patterns", "names", "rule_ids", "policies", "severities"}
    n = 3
    for key in ("patterns", "names", "rule_ids", "policies", "severities"):
        assert len(eng[key]) == n, key


def test_build_engine_defaults_and_invalid_regex():
    eng = build_engine(_rules())
    # Upper-cased ASCII policies, severity map with unknown -> Medium(1).
    assert eng["policies"] == [b"ALERT", b"BLOCK", b"ALERT"]
    assert eng["severities"] == [2, 3, 1]
    assert eng["rule_ids"][0] == b"R0056"
    # Invalid regex compiles to None (skipped at scan, never raises).
    assert eng["patterns"][2] is None
    # Sparse rule degrades to documented defaults, never raises.
    sparse = build_engine({"nids_rules": [{}]})
    assert sparse["rule_ids"] == [b"UNKNOWN"]
    assert sparse["severities"] == [1]
    assert sparse["patterns"] == [None]


def test_scan_first_match_wins_and_miss_returns_none():
    eng = build_engine(_rules())
    hit = scan_cython("GET /x?a=1' OR '1'='1", eng)
    assert hit is not None
    name, policy, rule_id, severity, index = hit
    assert (name, policy, rule_id, severity, index) == (b"sqli", b"ALERT", b"R0056", 2, 0)
    assert scan_cython("GET /index.html", eng) is None
    assert scan_cython("anything", build_engine({"nids_rules": []})) is None
