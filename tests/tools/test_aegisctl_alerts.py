"""F1: aegisctl alerts helpers stay pure and correctly derived.

Pins the three pure functions behind `aegisctl.py alerts`:
  - _fnv1a32 matches the Zig loader / Go nose numeric rule IDs. The two
    vectors are not invented: 3813986375 (R1001) and 3730098280 (R1004)
    were observed live in the deployed forensic ring (EVT-119 era).
  - _select_alerts keeps only rule matches and never lets one malformed
    record hide the rest.
  - _enrich_alert labels known numerics and keeps unknown numerics
    visible as UNKNOWN_RULE instead of dropping them.

Read-only: imports the CLI module (import-guarded, no side effects),
writes nothing to the tree, contacts no daemon.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"


def _load_cli():
    # aegisctl.py imports its control_api subpackage as `aegisctl.api.*`,
    # which resolves with tools/ on sys.path (test-process only).
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    spec = importlib.util.spec_from_file_location(
        "aegisctl_under_test", TOOLS_DIR / "aegisctl.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["aegisctl_under_test"] = module
    spec.loader.exec_module(module)
    return module


cli = _load_cli()


def test_fnv1a32_matches_live_rule_numerics():
    assert cli._fnv1a32("R1001") == 3813986375
    assert cli._fnv1a32("R1004") == 3730098280
    assert cli._fnv1a32("") == 0x811C9DC5


def test_select_alerts_keeps_only_matches():
    records = [
        {"record_seq": 1, "rule_id": 0},
        {"record_seq": 2, "rule_id": 3730098280, "source_name": "host_telemetry",
         "event_id": 9, "payload_len": 100, "verified": True},
        {"record_seq": 3},  # no rule_id at all
        {"record_seq": 4, "rule_id": "not-a-number"},  # malformed, skipped
        "garbage",  # non-dict, skipped
        None,
    ]
    alerts = cli._select_alerts(records)
    assert [a["record_seq"] for a in alerts] == [2]
    assert alerts[0]["rule_num"] == 3730098280


def test_enrich_alert_labels_known_and_unknown():
    by_num = {3730098280: {"rule_id": "R1004", "name": "DLL Drop in System32",
                           "severity": "Critical", "action": "Drop"}}
    known = cli._enrich_alert({"rule_num": 3730098280}, by_num)
    assert known["rule_id"] == "R1004"
    assert known["severity"] == "Critical"
    unknown = cli._enrich_alert({"rule_num": 12345}, by_num)
    assert unknown["rule_id"] == "UNKNOWN_RULE"
    assert unknown["rule_num"] == 12345


def test_enrich_alert_names_the_native_registry_rules():
    # ALERT-MAP-001: ids 1/2/3 are the native registry monitor's own rule ids,
    # not catalog FNV hashes; they must not surface as UNKNOWN_RULE.
    for num, expected in ((1, "REG-HKLM-RUN"), (2, "REG-HKLM-SERVICES"), (3, "REG-HKCU-RUN")):
        alert = cli._enrich_alert({"rule_num": num}, {})
        assert alert["rule_id"] == expected
        assert alert["severity"] == "High"
