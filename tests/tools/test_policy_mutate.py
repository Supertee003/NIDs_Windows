"""POLICY-MUTATE-001: evidence-verdict verbs are real, privileged and honest.

E2 proof of the CLI postcondition contract plus static proof that the Zig gate
suppresses only the policy evidence label — never a rule match, the forensic
record, or the PEP branch. No test writes to the tracked tree.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO / "tools"


def _load_cli():
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    spec = importlib.util.spec_from_file_location("aegisctl_policy_under_test", TOOLS_DIR / "aegisctl.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = _load_cli()


def _calls(response, sink):
    def fake(command, payload=None):
        sink.append((command, payload))
        return response
    return fake


def test_enable_reports_active_postcondition_and_no_host_effect(capsys, monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "CONTROL_API_AVAILABLE", True)
    monkeypatch.setattr(cli, "query_control", _calls(
        {"status": "ENABLED", "postcondition": "ACTIVE", "enabled": True, "generation": 4}, seen))
    assert cli._policy_mutation("enable") == 0
    assert seen == [("policy.enable", None)]
    payload = json.loads(capsys.readouterr().out)
    assert payload["postcondition"] == "ACTIVE"
    assert payload["evidence_verdict_enabled"] is True
    assert payload["generation"] == 4
    assert payload["detection_gated"] is False
    assert payload["host_effect"] is False


def test_disable_reports_active_postcondition(capsys, monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "CONTROL_API_AVAILABLE", True)
    monkeypatch.setattr(cli, "query_control", _calls(
        {"status": "DISABLED", "postcondition": "ACTIVE", "enabled": False, "generation": 5}, seen))
    assert cli._policy_mutation("disable") == 0
    assert seen == [("policy.disable", None)]
    payload = json.loads(capsys.readouterr().out)
    assert payload["evidence_verdict_enabled"] is False
    assert payload["detection_gated"] is False


def test_reload_proves_a_real_swap_before_claiming_success(capsys, monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "CONTROL_API_AVAILABLE", True)
    monkeypatch.setattr(cli, "query_control", _calls(
        {"status": "reloaded", "postcondition": "ACTIVE", "policies_loaded": 23,
         "previous_policies_loaded": 23, "generation": 6}, seen))
    assert cli._policy_mutation("reload") == 0
    assert seen == [("policy.reload", None)]
    payload = json.loads(capsys.readouterr().out)
    assert payload["policies_loaded"] == 23
    assert payload["generation"] == 6
    assert payload["host_effect"] is False


def test_reload_with_zero_policies_is_not_a_success(capsys, monkeypatch):
    monkeypatch.setattr(cli, "CONTROL_API_AVAILABLE", True)
    monkeypatch.setattr(cli, "query_control", _calls(
        {"status": "reloaded", "postcondition": "ACTIVE", "policies_loaded": 0}, []))
    assert cli._policy_mutation("reload") == 1
    assert json.loads(capsys.readouterr().out)["postcondition"] == "ACTIVE"  # reported, not trusted


def test_missing_postcondition_never_reports_success(capsys, monkeypatch):
    monkeypatch.setattr(cli, "CONTROL_API_AVAILABLE", True)
    monkeypatch.setattr(cli, "query_control", _calls(
        {"status": "ENABLED", "enabled": True}, []))
    assert cli._policy_mutation("enable") == 1
    assert json.loads(capsys.readouterr().out)["postcondition"] is None


def test_no_daemon_fails_closed(capsys, monkeypatch):
    monkeypatch.setattr(cli, "CONTROL_API_AVAILABLE", True)
    monkeypatch.setattr(cli, "query_control", _calls(None, []))
    assert cli._policy_mutation("enable") == 3
    assert capsys.readouterr().out == ""


def test_mutation_never_writes_local_state():
    source = (TOOLS_DIR / "aegisctl.py").read_text(encoding="utf-8")
    start = source.index("def _policy_mutation")
    end = source.index("def cmd_policy", start)
    body = source[start:end]
    for forbidden in ("open(", "write_text", "json.dump(", "disabled_rules.json", "_load_state"):
        assert forbidden not in body


def test_zig_gate_suppresses_only_the_evidence_verdict():
    src = (REPO / "src" / "pipeline" / "event_processor.zig").read_text(encoding="utf-8")
    assert "if (state.effectivePolicySet(ps)) |eval_ps| {" in src
    assert "if (eval_ps.evaluate(eval_ctx)) |pol| {" in src
    # The rule-id / host-source condition stays OUTSIDE the gate: detection
    # itself is never controlled by the policy flag.
    assert "if (matched_rule_id != 0 and !isHostTelemetrySource(ev.source)) {" in src
    gate_at = src.index("if (state.effectivePolicySet(ps))")
    pep_at = src.index("var pep_decision: pep.PepDecision", gate_at)
    for forbidden in ("g_prevention_gate_open", "pep_enf.enforce", "dispatchWithReceipt"):
        assert forbidden not in src[gate_at:pep_at]

    state_src = (REPO / "src" / "pipeline" / "runtime_state.zig").read_text(encoding="utf-8")
    assert "pub fn effectivePolicySet" in state_src
    assert "pub fn publishPolicySet" in state_src
    assert "pub fn freeRetiredPolicySets" in state_src
    daemon_src = (REPO / "src" / "daemon.zig").read_text(encoding="utf-8")
    assert "defer state.freeRetiredPolicySets();" in daemon_src
