"""DETECTION-CONTRACT-PIN-001: one rule set, one rule-id space, one match field.

Detection happens in exactly one tier: the Zig core builds an Aho-Corasick
automaton from `configs/Rules.json` and decides matches. Go Nose acquires and
frames evidence; it owns no rule file, no pattern matcher and no verdict
(VERDICT-AUTH-001, #28 — the classifier that used to mirror this contract was
deleted, and any acquisition-authored verdict is now stripped at Zig ingress).

Contract pinned here:
  AC1. The one detection tier reads configs/Rules.json through the bundle
       resolver and builds its automaton from `match_pattern`. Acquisition
       tiers read no rule file at all.
  AC2. `regex_pattern` is owned by the Python Brain path only.
  AC3. The rule-id hash (FNV-1a over the rule_id string) is identical in the
       Python reference, the Zig detector and the CLI, asserted against one
       golden table.
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
NOSE_DIR = REPO_ROOT / "nose"
GO_CLASSIFIER = NOSE_DIR / "signature_classifier.go"
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

    Zig spells it `"R0056", .hash = 2107512682`.
    """
    table: dict[str, int] = {}
    for rid, value in re.findall(r'"(R\d{4})"\s*:\s*(\d+)', source):
        table[rid] = int(value)
    for digits, value in re.findall(r'"R(\d{4})"\s*,\s*\.hash\s*=\s*(\d+)', source):
        table[f"R{digits}"] = int(value)
    return table


def _nose_sources() -> list[Path]:
    return sorted(p for p in NOSE_DIR.glob("*.go") if not p.name.endswith("_test.go"))


# ── AC1: one tier reads the file ───────────────────────────────────────────

def test_one_detection_tier_reads_the_canonical_rule_file():
    zig = ZIG_LOADER.read_text(encoding="utf-8")
    assert "runtime_paths.configPath" in zig, (
        "the Zig loader must resolve configs/Rules.json through the shared "
        "bundle resolver, not the process working directory"
    )
    assert 'get("match_pattern")' in zig
    assert "nids_rules" in zig

    brain = BRAIN.read_text(encoding="utf-8")
    assert "configs" in brain and "Rules.json" in brain


def test_no_acquisition_tier_owns_a_rule_file():
    """VERDICT-AUTH-001 (#28): no rule loader may exist outside the one tier.

    The deleted `nose/signature_classifier.go` read `configs/Rules.json`,
    decoded `match_pattern`, and wrote `rule_id`/`severity` onto the wire — a
    second detection authority. Evidence, not a comment, keeps it gone.
    """
    assert not GO_CLASSIFIER.exists(), (
        "the Go signature classifier must stay deleted: acquisition reports "
        "evidence, Zig owns the verdict (#28)"
    )
    for path in _nose_sources():
        source = path.read_text(encoding="utf-8")
        assert "AEGIS_RULES_PATH" not in source, f"{path.name} must not load a rule file"
        assert 'json:"match_pattern"' not in source, (
            f"{path.name} must not decode rule patterns"
        )
        assert "match_pattern" not in source, (
            f"{path.name} must not reference match_pattern at all"
        )


def test_fast_pattern_is_fixture_marker_only():
    """AC1c: fast_pattern gates nothing in production. It is a synthetic
    marker (fixture signals prepend it; the observe-only harness checks
    it alongside regex), not packet content — R0088's "PATH_TRAV" never
    appears in real traversal traffic, so gating match/regex on it would
    silence real detections. Zig must not read it, and the acquisition tier
    has no matcher left to read it with."""
    zig = ZIG_LOADER.read_text(encoding="utf-8")
    assert "fast_pattern" not in zig, (
        "the Zig automaton loader must build from match_pattern directly, never gate on fast_pattern"
    )
    for path in _nose_sources():
        source = path.read_text(encoding="utf-8")
        assert "fast_pattern" not in source and "FastPattern" not in source, (
            f"{path.name} must not gate on fast_pattern"
        )
    # The fast→regex chain lives in the synthetic harness, where it belongs.
    harness = (REPO_ROOT / "scripts" / "run_rule_matching_observe_only.py").read_text(encoding="utf-8")
    assert "fast_pattern" in harness and "regex_pattern" in harness


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
    # BE-DRIFT-098: one shared classifyRule serves both the startup and
    # reload loaders (stronger than the old two-call-site count — a single
    # classifier cannot disagree with itself about what a pattern is).
    assert zig.count('get("match_pattern")') == 1, "match_pattern must be read in exactly one place"
    assert "classifyRule" in zig
    assert "reloadRules" in zig and "loadRulesInto" in zig
    assert "regex_pattern" not in zig, "the Zig automaton must not compile regex patterns"
    assert "hashRuleId" in zig


# ── AC2/AC3: one rule-id space ─────────────────────────────────────────────

def test_rule_id_hashes_are_identical_across_python_and_zig():
    golden = {rule["rule_id"]: _fnv1a32(rule["rule_id"]) for rule in _canonical_rules()}
    # Explicit census (not len()): adding a rule must update the Zig table in
    # the same patch, or the comparison below fails.
    assert set(golden) == {
        "R0056", "R0088", "R0089", "R1001", "R1002", "R1003", "R1004",
        "R1005", "R2001", "R2002", "R2003", "R2004", "R2005", "R3001",
        "R3002", "R3003", "R3004", "R3005", "R9002", "R9006", "R9007",
        "R9059", "R9064",
    }, sorted(set(golden))

    zig_table = _golden_from(ZIG_LOADER.read_text(encoding="utf-8"))

    assert zig_table == golden, "the Zig detector's rule-id space drifted from the canonical table"


def test_rule_id_hash_is_fnv1a_in_the_compiled_tier():
    source = ZIG_LOADER.read_text(encoding="utf-8")
    assert "0x811c9dc5" in source, "rule_loader.zig must use the FNV-1a offset basis"
    assert "0x01000193" in source, "rule_loader.zig must use the FNV-1a prime"


def test_cli_rule_hash_joins_the_shared_table():
    # EVT-176: `forensic search --field rule` hashes catalog ids
    # client-side, so the CLI joins the Zig/Python agreement as another
    # implementation. Bare integers pass through untouched.
    from tools.aegisctl.api.control_api import rule_id_to_u32
    golden = {rule["rule_id"]: _fnv1a32(rule["rule_id"]) for rule in _canonical_rules()}
    for rid, want in golden.items():
        assert rule_id_to_u32(rid) == want, rid
    assert rule_id_to_u32("R9059") == 4009890390
    assert rule_id_to_u32("4009890390") == 4009890390
    for bad in ("", "   "):
        try:
            rule_id_to_u32(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("empty rule id must raise, not hash")


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
# In Project 2 observe-only mode the detection tier never branches on a rule's
# `action`. Enforcement comes only from configs/policies.json through the Rust
# PEP receipt path while the prevention gate is the authority. If a new action
# value appears, or any tier starts reading it, this pin fails loudly so the
# coupling is a conscious contract change — not a silent promotion to host
# effect.

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
    for path in _nose_sources():
        source = path.read_text(encoding="utf-8")
        assert 'json:"action"' not in source, (
            f"{path.name} must not decode a rule action: acquisition tiers submit no policy decision"
        )
        assert "rule.Action" not in source, (
            f"{path.name} must not branch on a rule action"
        )


# ── AC7: the 32-bit rule-id space has no collisions ─────────────────────────
#
# rule_id strings hash (FNV-1a) into the same u32 space the correlator's
# 9000-block count rules live in. Two collisions would each be a
# detection-identity bug: a signature hit attributed to the wrong rule,
# or a hash landing inside the count-rule block (9000-9999, reserved by
# Correlator.dnsExfilRule and friends for multi-event rules that never
# come from FNV). With ~23 IDs in 2^32 the odds are nil — this test
# makes "nil" a checked fact instead of luck, and fails loudly the day
# a new rule_id lands on an occupied value.

CORRELATOR_BLOCK_LO = 9000
CORRELATOR_BLOCK_HI = 9999


def test_rule_id_hashes_have_no_collisions():
    seen: dict[int, str] = {}
    for rule in _canonical_rules():
        rid = rule["rule_id"]
        digest = _fnv1a32(rid)
        assert digest not in seen, (
            f"FNV-1a collision: {rid!r} and {seen[digest]!r} both hash to "
            f"{digest} — one rule would shadow the other"
        )
        seen[digest] = rid


def test_no_signature_hash_lands_in_the_correlator_block():
    for rule in _canonical_rules():
        digest = _fnv1a32(rule["rule_id"])
        assert not (CORRELATOR_BLOCK_LO <= digest <= CORRELATOR_BLOCK_HI), (
            f"{rule['rule_id']!r} hashes to {digest}, inside the reserved "
            f"correlator block {CORRELATOR_BLOCK_LO}-{CORRELATOR_BLOCK_HI}"
        )


@pytest.mark.skipif(shutil.which("go") is None, reason="Go toolchain not installed")
def test_nose_package_still_builds_without_the_classifier():
    """The acquisition tier must keep compiling after its matcher was removed:
    a deleted classifier that leaves dangling references would only surface at
    install time, on the host."""
    completed = subprocess.run(
        ["go", "build", "-o", str(Path(__file__).with_name("_nose_probe.exe")), "."],
        cwd=NOSE_DIR.resolve(), capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    try:
        assert completed.returncode == 0, completed.stdout + completed.stderr
    finally:
        Path(__file__).with_name("_nose_probe.exe").unlink(missing_ok=True)
