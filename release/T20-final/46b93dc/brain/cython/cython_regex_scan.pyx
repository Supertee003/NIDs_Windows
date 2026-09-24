# cython_regex_scan.pyx — T5b Cython accelerator for the AEGIS Brain regex scan loop
#
# Replaces the per-iteration Python loop in `brain/windows_brain.run_regex_scan`
# with a C-level loop that iterates a pre-built list of compiled re.Pattern
# objects. The loop and per-iteration bookkeeping (counter, return-tuple
# assembly) runs at C speed; the per-rule `re.Pattern.search()` call still
# goes through the Python API but no longer pays Python loop overhead.
#
# The Python `re` module is the canonical implementation; this module is a
# thin wrapper. The Cython contribution is:
#   1. Eliminate the per-iteration Python `for r in rules_data...` overhead
#   2. Eliminate the per-iteration `tier2_engine.get(name)` dict lookup
#   3. Eliminate the per-iteration `r.get("name", "")`, `r.get("rule_id", ...)`,
#      `r.get("action", "Alert")`, `r.get("severity", "Medium")` lookups
#   4. Eliminate the per-iteration severity_map construction
#   5. Assemble the (name, policy, rule_id, severity) tuple at C speed
#
# Authority constraints (AC4):
#   - This module has NO path to policy, PEP, or Windows privilege.
#   - It only does `re.Pattern.search(payload)` and returns Python-level
#     strings/ints that the CALLER uses to make a policy decision.
#   - It does NOT call `netsh`, does NOT touch the firewall, does NOT call
#     into the Rust PEP, does NOT write to the registry, does NOT call any
#     subprocess, does NOT access the C++ Bridge. It is a pure string-search
#     helper.

from libc.stdint cimport int64_t
import re

# Cached severity map (mirrors the one in windows_brain.run_regex_scan)
cdef dict _SEVERITY_MAP = {
    b"Low": 0,
    b"Medium": 1,
    b"High": 2,
    b"Critical": 3,
    "Low": 0,
    "Medium": 1,
    "High": 2,
    "Critical": 3,
}


def build_engine(rules_data):
    """Pre-build a parallel-array engine from Rules.json.

    Returns a dict with three lists, all of the same length N (one per rule):
      - patterns:  list[re.Pattern]   (the compiled regex; empty for non-matching rules)
      - names:     list[bytes]         (UTF-8 rule name; "" if missing)
      - rule_ids:  list[bytes]         (UTF-8 rule_id; b"UNKNOWN" if missing)
      - policies:  list[bytes]         (UTF-8 action uppercased; b"ALERT" if missing)
      - severities: list[int]          (0..3, default 1)

    This is the Python-side equivalent of `compile_tier2_rules` but
    pre-computes EVERYTHING the scan loop will need. The scan loop can then
    do a pure C-level iteration.
    """
    cdef int i
    n = len(rules_data.get("nids_rules", []))
    patterns = []
    names = []
    rule_ids = []
    policies = []
    severities = []
    for r in rules_data.get("nids_rules", []):
        name = r.get("name", "") or ""
        rule_id = r.get("rule_id", "UNKNOWN") or "UNKNOWN"
        regex_str = r.get("regex_pattern", "") or ""
        match_str = r.get("match_pattern", "") or ""
        action = r.get("action", "Alert") or "Alert"
        severity_str = r.get("severity", "Medium") or "Medium"

        # Prefer regex_pattern first (most specific)
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
        sev = _SEVERITY_MAP.get(severity_str)
        if sev is None:
            sev = 1
        severities.append(sev)
    return {
        "patterns": patterns,
        "names": names,
        "rule_ids": rule_ids,
        "policies": policies,
        "severities": severities,
    }


def scan_cython(str payload, dict engine):
    """Cython scan: iterate the pre-built engine at C speed.

    Returns a 5-tuple (name, policy, rule_id, severity, index) on the first
    match, or None if no rule matched.

    Why index is in the tuple: the caller (run_regex_scan in windows_brain.py)
    may want it for diagnostics; the canonical return shape is the 4-tuple
    (name, policy, rule_id, severity) so callers that don't care about the
    index can unpack the first four.

    Note: payload is `str`, not `bytes`, to match the contract of
    `windows_brain.run_regex_scan` which does `str(payload)[:MAX_PAYLOAD_SIZE]`
    before calling. The compiled `re.Pattern` objects are also str-patterns.
    """
    cdef:
        list patterns = engine["patterns"]
        list names = engine["names"]
        list rule_ids = engine["rule_ids"]
        list policies = engine["policies"]
        list severities = engine["severities"]
        int n = len(patterns)
        int i
        object pat

    for i in range(n):
        pat = patterns[i]
        if pat is None:
            continue
        if pat.search(payload):
            return (names[i], policies[i], rule_ids[i], severities[i], i)
    return None
