"""Pure-Python fallback for `brain.cython.cython_regex_scan`.

Used when the Cython extension is not compiled. The shape and return values
MUST match the Cython module exactly (build_engine returns a dict with the
same five lists; scan_cython returns a 5-tuple on match, None otherwise).

Authority (T5b AC4):
  Pure-Python only. No subprocess, no os.system, no ctypes, no firewall
  / WFP / Rust-PEP binding. This file is loaded in CI without the Cython
  extension compiled, so it serves as the AC4 evidence.
"""
from __future__ import annotations

import re
from typing import Any

_SEVERITY_MAP: dict = {
    "Low": 0,
    "Medium": 1,
    "High": 2,
    "Critical": 3,
}


def build_engine(rules_data: dict) -> dict[str, list]:
    """Pre-build a parallel-array engine from Rules.json.

    See brain/cython/cython_regex_scan.pyx for the contract. The shape of
    the returned dict must match exactly.
    """
    patterns: list = []
    names: list[bytes] = []
    rule_ids: list[bytes] = []
    policies: list[bytes] = []
    severities: list[int] = []

    for r in rules_data.get("nids_rules", []):
        name = r.get("name", "") or ""
        rule_id = r.get("rule_id", "UNKNOWN") or "UNKNOWN"
        regex_str = r.get("regex_pattern", "") or ""
        match_str = r.get("match_pattern", "") or ""
        action = r.get("action", "Alert") or "Alert"
        severity_str = r.get("severity", "Medium") or "Medium"

        if regex_str:
            try:
                pat = re.compile(regex_str, re.DOTALL)
            except Exception:
                pat = None
        elif match_str:
            try:
                escaped = re.escape(match_str)
                escaped = escaped.replace(r"\\x", r"\x")
                pat = re.compile(escaped, re.DOTALL)
            except Exception:
                pat = None
        else:
            pat = None

        patterns.append(pat)
        names.append(name.encode("utf-8") if isinstance(name, str) else name)
        rule_ids.append(rule_id.encode("utf-8") if isinstance(rule_id, str) else rule_id)
        policies.append(action.upper().encode("utf-8") if isinstance(action, str) else action)
        severities.append(_SEVERITY_MAP.get(severity_str, 1))

    return {
        "patterns": patterns,
        "names": names,
        "rule_ids": rule_ids,
        "policies": policies,
        "severities": severities,
    }


def scan_cython(payload: str, engine: dict[str, list]) -> tuple | None:
    """Pure-Python scan: equivalent to the Cython version's loop.

    Returns a 5-tuple (name, policy, rule_id, severity, index) on the first
    match, or None. The Cython version runs this loop at C speed; this
    version uses a Python for-loop and is used as a correctness oracle and
    a fallback when Cython is not compiled.
    """
    patterns: list = engine["patterns"]
    names: list[bytes] = engine["names"]
    rule_ids: list[bytes] = engine["rule_ids"]
    policies: list[bytes] = engine["policies"]
    severities: list[int] = engine["severities"]

    for i, pat in enumerate(patterns):
        if pat is None:
            continue
        if pat.search(payload):
            return (names[i], policies[i], rule_ids[i], severities[i], i)
    return None
