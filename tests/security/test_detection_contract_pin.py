"""DETECTION-CONTRACT-PIN-001: one rule set, one rule-id space, one match field.

Detection happens in two engines: the Go nose classifier matches real packet
payloads at capture time, and the Zig core builds an Aho-Corasick automaton from
the same file. They must agree on the file, the field and the numeric rule id,
or a detection attributed by one tier names a different rule in the other.

Contract pinned here:
  AC1. All tiers read configs/Rules.json; the Go classifier matches
       `match_pattern` and the Zig automaton is built from `match_pattern`.
  AC2. `regex_pattern` is owned by the Python Brain path only.
  AC3. The rule-id hash (FNV-1a over the rule_id string) is identical in
       Python, Go and Zig, asserted against one golden table.
  AC4. The canonical file declares both fields for every rule.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RULES = REPO_ROOT / "configs" / "Rules.json"
GO_CLASSIFIER = REPO_ROOT / "nose" / "signature_classifier.go"
GO_TEST = REPO_ROOT / "nose" / "signature_classifier_test.go"
ZIG_LOADER = REPO_ROOT / "src" / "pipeline" / "rule_loader.zig"
BRAIN = REPO_ROOT / "brain" / "windows_brain.py"


def _fnv1a32(value: str) -> int:
    """Independent FNV-1a implementation used to compute the golden table."""
    digest = 0x811C9DC5
    for byte in value.encode("utf-8"):
        digest ^= byte
        digest = (digest * 0x01000193) & 0xFFFFFFFF
    return digest


def _canonical_rules() -> list[dict]:
    return json.loads(RULES.read_text(encoding="utf-8"))["nids_rules"]


def _golden_from(source: str) -> dict[str, int]:
    """Extract the shared golden rule-id table from tier test code.

    Go spells it `"R0056": 2107512682` and Zig `"R0056", .hash = 2107512682`.
    """
    table: dict[str, int] = {}
    for rid, value in re.findall(r'"(R\d{4})"\s*:\s*(\d+)', source):
        table[rid] = int(value)
    for digits, value in re.findall(r'"R(\d{4})"\s*,\s*\.hash\s*=\s*(\d+)', source):
        table[f"R{digits}"] = int(value)
    return table


# ── AC1: same file, same field ─────────────────────────────────────────────

def test_every_detection_tier_reads_the_canonical_rule_file():
    go = GO_CLASSIFIER.read_text(encoding="utf-8")
    assert 'path = "configs/Rules.json"' in go
    assert "AEGIS_RULES_PATH" in go, "the classifier must allow an explicit rule path override"
    assert 'json:"match_pattern"' in go

    zig = ZIG_LOADER.read_text(encoding="utf-8")
    assert 'runtime_paths.configPath' in zig, (
        "the Zig loader must resolve configs/Rules.json through the shared "
        "bundle resolver, not the process working directory"
    )
    assert 'get("match_pattern")' in zig
    assert "nids_rules" in zig

    brain = BRAIN.read_text(encoding="utf-8")
    assert "configs" in brain and "Rules.json" in brain


def test_go_classifier_matches_the_match_pattern_by_substring():
    go = GO_CLASSIFIER.read_text(encoding="utf-8")
    assert "strings.Contains(string(payload), rule.MatchPattern)" in go, (
        "the Go classifier must be pinned to case-sensitive substring matching"
    )
    assert "regex_pattern" not in go, "regex_pattern is owned by the Python Brain path"


def test_zig_startup_uses_the_shared_bundle_resolver():
    """AC1b: a service (cwd=C:\\WINDOWS\\system32) must still find its rules.

    Both the startup loader in daemon.zig and the hot-reload loader must go
    through src/core/runtime_paths.zig; a bare relative path here silently
    disables the detection engine under the Windows service.
    """
    daemon = (REPO_ROOT / "src" / "daemon.zig").read_text(encoding="utf-8")
    assert "runtime_paths.resolveRoot" in daemon
    assert 'runtime_paths.configPath' in daemon
    assert 'openFile("configs/Rules.json"' not in daemon, (
        "daemon.zig must not open a cwd-relative rule path"
    )

    resolver = (REPO_ROOT / "src" / "core" / "runtime_paths.zig").read_text(encoding="utf-8")
    assert "selfExeDirPathAlloc" in resolver, (
        "bundle resolution must derive from the executable location"
    )
    assert "hasRequiredConfig" in resolver


def test_zig_automaton_is_built_from_match_pattern_not_regex():
    zig = ZIG_LOADER.read_text(encoding="utf-8")
    assert zig.count('get("match_pattern")') == 2, "both the startup and reload loaders load it"
    assert "regex_pattern" not in zig, "the Zig automaton must not compile regex patterns"
    assert "hashRuleId" in zig


# ── AC2/AC3: one rule-id space ─────────────────────────────────────────────

def test_rule_id_hashes_are_identical_across_python_go_and_zig():
    golden = {rule["rule_id"]: _fnv1a32(rule["rule_id"]) for rule in _canonical_rules()}
    assert len(golden) == 22

    go_table = _golden_from(GO_TEST.read_text(encoding="utf-8"))
    zig_table = _golden_from((ZIG_LOADER.parent / "rule_loader.zig").read_text(encoding="utf-8"))

    assert go_table == golden, "the Go classifier's rule-id space drifted from the canonical table"
    assert zig_table == golden, "the Zig detector's rule-id space drifted from the canonical table"


def test_rule_id_hash_is_fnv1a_in_both_compiled_tiers():
    for path in (GO_CLASSIFIER, ZIG_LOADER):
        source = path.read_text(encoding="utf-8")
        assert "0x811c9dc5" in source, f"{path.name} must use the FNV-1a offset basis"
        assert "0x01000193" in source, f"{path.name} must use the FNV-1a prime"


# ── AC4: the canonical file carries both fields for every rule ─────────────

def test_every_canonical_rule_declares_both_pattern_fields():
    for rule in _canonical_rules():
        assert rule.get("rule_id"), rule
        assert rule.get("match_pattern"), f"{rule['rule_id']} needs a match_pattern"
        assert rule.get("regex_pattern"), f"{rule['rule_id']} needs a regex_pattern"


# ── AC6: match_pattern strings are unique ────────────────────────────────────
#
# The Zig automaton stores per-terminal-state outputs as (start, count)
# into one shared list, which is only correct when no two patterns end at
# the same state — i.e. no duplicate match_pattern strings. A duplicate
# would read a neighboring rule's id (output aliasing). Fixing the
# automaton for ambiguous same-bytes rules needs a rule-owner verdict
# (priority? first-wins?), so the contract instead keeps the edge
# unreachable: every canonical rule carries a distinct non-empty pattern.


def test_match_patterns_are_unique_and_nonempty():
    seen: dict[str, str] = {}
    for rule in _canonical_rules():
        pattern = rule.get("match_pattern", "")
        assert isinstance(pattern, str) and len(pattern) > 0, (
            f"{rule.get('rule_id')} needs a non-empty match_pattern"
        )
        assert pattern not in seen, (
            f"duplicate match_pattern {pattern!r} in {rule.get('rule_id')} "
            f"and {seen[pattern]} would alias automaton outputs"
        )
        seen[pattern] = rule.get("rule_id", "?")

# ── AC5: rule action is an advisory label, never an enforcement order ──────
#
# In Project 2 observe-only mode the detection tiers (Zig AC, Go substring)
# never branch on a rule's `action`. Enforcement comes only from
# configs/policies.json through the Rust PEP receipt path while the
# prevention gate is the authority. If a new action value appears, or any
# tier starts reading it, this pin fails loudly so the coupling is a
# conscious contract change — not a silent promotion to host effect.

ADVISORY_RULE_ACTIONS = {"Drop", "Block", "Alert"}


def test_rule_actions_stay_within_the_advisory_vocabulary():
    seen = set()
    for rule in _canonical_rules():
        action = rule.get("action")
        assert action, f"{rule.get('rule_id')} needs an action label"
        seen.add(action)
    unknown = seen - ADVISORY_RULE_ACTIONS
    assert not unknown, f"new rule action(s) {sorted(unknown)} need a contract review first"


def test_no_detection_tier_branches_on_rule_action():
    zig = ZIG_LOADER.read_text(encoding="utf-8")
    assert 'get("action")' not in zig, (
        "the Zig automaton loader must not read rule actions; "
        "enforcement is owned by policies.json through the Rust PEP"
    )
    go = GO_CLASSIFIER.read_text(encoding="utf-8")
    assert "Action" not in go, (
        "the Go classifier struct must not carry an action field"
    )


@pytest.mark.skipif(shutil.which("go") is None, reason="Go toolchain not installed")
def test_go_classifier_suite_pins_the_shared_golden_table():
    nose_dir = (REPO_ROOT / "nose").resolve()
    completed = subprocess.run(
        ["go", "test", "-run", "RuleHashes|ClassifierMatches", "."],
        cwd=nose_dir, capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
