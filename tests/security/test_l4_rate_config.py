"""RB-021-L4-RATE: canonical L4 rate/window configuration pins.

The Zig matcher owns the state machine; this test keeps the canonical
Rules.json and the rule-22 vectors from drifting away from the three
documented semantics:

  R9002  count >= 50 ICMP packets per source per 1000 ms
  R9006  >= 20 distinct destination ports per source per 10000 ms
  R9007  exact FIN|PSH|URG, per-packet (no rate block)

A missing or malformed rate block makes the Zig parser reject the rule, so
these are contract pins, not tuning suggestions.
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RULES = REPO / "configs" / "Rules.json"
VECTORS = REPO / "tests" / "vectors" / "rules22"


def _load_rules() -> dict[str, dict]:
    document = json.loads(RULES.read_text(encoding="utf-8"))
    return {rule["rule_id"]: rule for rule in document["nids_rules"]}


def test_canonical_l4_rate_blocks() -> None:
    rules = _load_rules()

    icmp = rules["R9002"]
    assert icmp["rate_mode"] == "count"
    assert icmp["rate_threshold"] == 50
    assert icmp["rate_window_ms"] == 1000

    syn = rules["R9006"]
    assert syn["rate_mode"] == "distinct_dst_ports"
    assert syn["rate_threshold"] == 20
    assert syn["rate_window_ms"] == 10000

    xmas = rules["R9007"]
    assert "rate_mode" not in xmas
    assert "rate_threshold" not in xmas
    assert "rate_window_ms" not in xmas


def test_rate_blocks_are_l4_only_and_well_formed() -> None:
    rules = _load_rules()
    for rule_id, rule in rules.items():
        if rule.get("layer") != "L4":
            assert "rate_mode" not in rule, f"{rule_id}: rate_mode is L4-only"
            assert "rate_threshold" not in rule, f"{rule_id}: threshold is L4-only"
            assert "rate_window_ms" not in rule, f"{rule_id}: window is L4-only"
            continue
        if "rate_mode" not in rule:
            continue
        assert rule["rate_mode"] in {"count", "distinct_dst_ports"}, rule_id
        assert isinstance(rule["rate_threshold"], int) and rule["rate_threshold"] > 0, rule_id
        assert isinstance(rule["rate_window_ms"], int) and rule["rate_window_ms"] > 0, rule_id
        if rule["rate_mode"] == "distinct_dst_ports":
            assert rule["rate_threshold"] <= 64, rule_id


def test_rule22_vectors_match_the_canonical_rate_blocks() -> None:
    rules = _load_rules()
    for rule_id in ("R9002", "R9006"):
        vector = json.loads((VECTORS / f"{rule_id}.json").read_text(encoding="utf-8"))
        canonical = rules[rule_id]
        assert vector["rate_mode"] == canonical["rate_mode"]
        assert vector["rate_threshold"] == canonical["rate_threshold"]
        assert vector["rate_window_ms"] == canonical["rate_window_ms"]
