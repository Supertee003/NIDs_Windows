#!/usr/bin/env python3
"""22-rule VM test kit runner (observe-only handoff).

Runs the full synthetic 22-rule kit in dependency order and collects every
output into vm_test_kit_22rules_<UTC timestamp>/ for handoff to VM testing:

  kit/
    README.md                  <- how to use on the VM + gate expectations
    run_manifest.json          <- commands, return codes, timestamps
    configs/Rules.json
    analysis/RULE_22_DETECTION_FIXTURE_MANIFEST.json
    analysis/RULE_22_OBSERVE_ONLY_MATCHING.json
    adapters.json / canaries/*.md / readiness.txt (captured outputs)

Safety: synthetic observe-only only. No enforcement, no mutation, no
network transmission. Prevention gate must read "closed" in every output.
Exit nonzero if any step fails.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
KIT = ROOT / f"vm_test_kit_22rules_{NOW}"

STEPS: list[tuple[str, list[str]]] = [
    ("generate_fixtures", [sys.executable, "scripts/generate_detection_fixture_manifest.py"]),
    ("validate_manifest", [sys.executable, "scripts/validate_detection_fixture_manifest.py"]),
    ("rule_matching", [sys.executable, "scripts/run_rule_matching_observe_only.py"]),
    ("adapters", [sys.executable, "scripts/run_synthetic_detection_adapters.py"]),
    ("canary_fim", [sys.executable, "scripts/fim_rule_canary_scan.py"]),
    ("canary_pipe", [sys.executable, "scripts/pipe_rule_canary_scan.py"]),
    ("canary_process", [sys.executable, "scripts/process_rule_canary_scan.py"]),
    ("readiness", [sys.executable, "scripts/pre_attack_readiness_scan.py"]),
]

CAPTURES = {
    "analysis/RULE_22_OBSERVE_ONLY_MATCHING.json": "RULE_22_OBSERVE_ONLY_MATCHING.json",
    "analysis/RULE_22_DETECTION_FIXTURE_MANIFEST.json": "RULE_22_DETECTION_FIXTURE_MANIFEST.json",
}

README = """# 22-Rule VM Test Kit ({ts}Z)

Synthetic observe-only kit. Prevention gate is CLOSED in every artifact:
nothing here enforces, mutates, transmits, or creates processes.

## On the VM
1. Copy this directory to the isolated Windows VM (host-only network).
2. Build all components (`scripts\\build_all.bat`).
3. Run the kit: `python scripts\\run_22rules_kit.py` (regenerates + re-verifies).
4. Sensor proofs per layer (need native events, still observe-only):
   - `run_etw_runtime_observe_only_proof.ps1` (L4/process)
   - `run_fim_runtime_observe_only_proof.ps1` (KERNEL_FILE)
   - `run_pipe_runtime_observe_only_proof.ps1` (L2_PIPE)
   - `run_wfp_hostonly_observe_only.ps1` (WFP L4)
   - `run_l7_hostonly_observe_only.ps1` (L7)
5. Kali (host-only): `scripts/kali_hostonly_probe.sh`, `scripts/kali_l7_benign_probe.sh`.
6. Controlled enforcement (CAUTION, separate reviewed step):
   `run_controlled_proof.ps1` — prevention gate must be opened explicitly first.

## Gates in this kit
- `run_manifest.json`: every step exit 0, or the kit FAILS.
- all-rules matching, 0 host effects, gate closed everywhere.
"""


def main() -> int:
    (KIT / "canaries").mkdir(parents=True, exist_ok=True)
    log: dict = {"schema": "aegis.22rule-kit-run.v1", "kit": KIT.name,
                 "created_at": NOW, "steps": []}
    failed = False
    for name, cmd in STEPS:
        started = datetime.now(timezone.utc).isoformat()
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        record = {"step": name, "cmd": cmd[1:], "rc": proc.returncode,
                  "started_at": started}
        out_file = KIT / ("canaries" if name.startswith("canary_") else "") / f"{name}.txt"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(proc.stdout + proc.stderr, encoding="utf-8")
        if proc.returncode != 0:
            record["error_tail"] = (proc.stdout + proc.stderr)[-500:]
            failed = True
        log["steps"].append(record)
        print(f"[{'OK' if proc.returncode == 0 else 'FAIL'}] {name}")
        if failed:
            break
    for src, dst in CAPTURES.items():
        p = ROOT / src
        if p.exists():
            shutil.copy(p, KIT / dst)
    shutil.copy(ROOT / "configs" / "Rules.json", KIT / "Rules.json")
    (KIT / "README.md").write_text(README.format(ts=NOW), encoding="utf-8")
    (KIT / "run_manifest.json").write_text(json.dumps(log, indent=2), encoding="utf-8")
    print(f"kit: {KIT}")
    print("PASS: rule kit complete" if not failed else "FAIL: kit incomplete, see run_manifest.json")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
