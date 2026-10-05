#!/usr/bin/env python3
"""Split the 22-rule kit into 22 standalone per-rule files (not combined).

Reads configs/Rules.json + analysis/RULE_22_DETECTION_FIXTURE_MANIFEST.json
and writes tests/vectors/rules22/<rule_id>.json — one self-contained file
per rule: definition, fixture, synthetic signal, expected result, VM steps.
Safe: observe-only strings only, prevention gate closed.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests" / "vectors" / "rules22"

LAYER_VM_STEPS = {
    "L7": ["replay payload via run_synthetic_detection_adapters.py",
           "host-only: kali_l7_benign_probe.sh, then malicious variant",
           "verify: L7 parser event + signature match, no enforcement"],
    "L4": ["host-only: kali_hostonly_probe.sh (nmap/hping3)",
           "verify: flow anomaly + rule match via metrics snapshot"],
    "KERNEL_FILE": ["run_fim_runtime_observe_only_proof.ps1 on the VM",
                    "verify: FIM event + hash mismatch, canonical event, forensic record"],
    "KERNEL_PROCESS": ["run_etw_runtime_observe_only_proof.ps1 on the VM",
                       "verify: ETW process event + pattern match, no process creation by test"],
    "L2_PIPE": ["run_pipe_runtime_observe_only_proof.ps1 on the VM",
                "verify: pipe event + name match, canonical event, forensic record"],
}


def main() -> int:
    rules = json.loads((ROOT / "configs" / "Rules.json").read_text(encoding="utf-8"))["nids_rules"]
    manifest = json.loads((ROOT / "analysis" / "RULE_22_DETECTION_FIXTURE_MANIFEST.json").read_text(encoding="utf-8"))
    by_rule = {f["rule_id"]: f for f in manifest["fixtures"]}
    assert len(rules) == len(by_rule) and len(rules) > 0, "rules and fixtures must agree 1:1"
    OUT.mkdir(parents=True, exist_ok=True)
    for r in rules:
        rid = r["rule_id"]
        f = by_rule[rid]
        marker = f["synthetic_input"]["marker"]
        # Same synthetic signal the observe-only harness builds (rule_matching
        # script appends a representative Windows path to every signal).
        sig = marker + " " + r["match_pattern"] + r" C:\Windows\System32\drivers\etc\hosts"
        try:
            regex_ok = bool(re.search(r["regex_pattern"], sig))
        except re.error:
            regex_ok = False
        doc = {
            "schema": "aegis.rule22-single.v1",
            "rule_id": rid,
            "name": r["name"],
            "layer": r["layer"],
            "severity": r["severity"],
            "action": r["action"],
            "patterns": {
                "fast_pattern": r["fast_pattern"],
                "match_pattern": r["match_pattern"],
                "regex_pattern": r["regex_pattern"],
            },
            "fixture": {
                "fixture_id": f["fixture_id"],
                "source": f["source"],
                "marker": marker,
                "synthetic_signal": sig,
                "regex_match": regex_ok,
            },
            "expected_observe_only": f["expected_observe_only"],
            "prevention_gate": "closed",
            "vm_steps": LAYER_VM_STEPS.get(r["layer"], ["follow kit README"]),
        }
        (OUT / f"{rid}.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(rules)} files to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
