"""EVT-197: every Kali lab script covers its rule (static proof).

23 rules, 23 scripts in scripts/kali_attacks/, all pinned without any
network: existence + syntax, the 192.168.126 lab-only refuse guard, and
for regex rules a real re.search of at least one script PAYLOAD against
the rule's regex (AST-extracted, so quoted payloads don't fool the
check -- a naive regex scrape false-flagged R0056). Behavioral scripts
(floods/scans/host canaries without PAYLOADS) pin guard + presence;
their wire semantics live in the lab runbook RB-021, proven live on the
VMs, never in the suite.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
KALI = REPO / "scripts" / "kali_attacks"


def _catalog():
    doc = json.loads((REPO / "configs" / "Rules.json").read_text(encoding="utf-8"))
    return {r["rule_id"]: r for r in doc["nids_rules"]}


def _scripts():
    out = {}
    for f in KALI.glob("R*.py"):
        m = re.match(r"(R\d+)_", f.name)
        if m:
            out[m.group(1)] = f
    return out


def _payloads_of(path: Path) -> list:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "PAYLOADS" for t in node.targets):
            try:
                val = ast.literal_eval(node.value)
            except (ValueError, SyntaxError):
                return []
            return [str(x) for x in val] if isinstance(val, list) else []
    return []


def test_every_rule_has_a_script():
    rules, scripts = _catalog(), _scripts()
    assert set(scripts) == set(rules), (
        "missing: %s extra: %s" % (set(rules) - set(scripts), set(scripts) - set(rules)))


def test_every_script_parses_and_refuses_non_lab():
    for rid, path in sorted(_scripts().items()):
        src = path.read_text(encoding="utf-8")
        ast.parse(src)  # syntax must hold
        assert "192.168.126." in src, f"{rid}: lab subnet guard missing"
        assert "REFUSE" in src, f"{rid}: refuse path missing"


def test_regex_rules_have_a_matching_payload():
    rules, scripts = _catalog(), _scripts()
    checked = 0
    for rid in sorted(rules):
        rx = rules[rid].get("regex_pattern", "")
        payloads = _payloads_of(scripts[rid])
        if not rx or not payloads:
            continue
        try:
            prog = re.compile(rx)
        except re.error:
            raise AssertionError(f"{rid}: rule regex does not compile")
        hits = [p for p in payloads if prog.search(p)]
        assert hits, (
            f"{rid}: none of {len(payloads)} script payloads match the rule "
            f"regex -- the lab run would not fire this rule")
        checked += 1
    assert checked >= 5, f"expected several regex-covered rules, got {checked}"
