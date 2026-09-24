from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANALYSIS = ROOT / "analysis"
LOCK = ANALYSIS / ".rules-22-run.lock"


def main() -> int:
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    try:
        with LOCK.open("x", encoding="utf-8") as handle:
            handle.write(f"pid={os.getpid()}\n")
    except FileExistsError:
        print(f"Active/stale lock exists: {LOCK}", file=sys.stderr)
        return 3

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S") + f"_{os.getpid()}"
    out_dir = ANALYSIS / f"rules-22-run-{stamp}"
    out_dir.mkdir()
    log_path = out_dir / "run.log"
    failures = 0

    def log(line: str) -> None:
        print(line, flush=True)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def run(label: str, args: list[str]) -> None:
        nonlocal failures
        log(f"[RUN] {label}: {' '.join(args)}")
        result = subprocess.run(
            args,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        with log_path.open("a", encoding="utf-8") as handle:
            if result.stdout:
                handle.write(result.stdout)
            if result.stderr:
                handle.write(result.stderr)
        if result.returncode:
            log(f"[FAIL] {label} exit={result.returncode}")
            failures += 1
        else:
            log(f"[PASS] {label}")

    log("AEGIS Rules-22 Safe Qualification")
    log(f"Root={ROOT}")
    log(f"Log={log_path}")
    log("Mode=synthetic_observe_only; prevention_gate=closed; host_effect_capable=false")

    run("rules schema/semantic validation", [sys.executable, "tools/aegisctl.py", "rules", "validate"])
    run("qualification matrix generation", [sys.executable, "scripts/generate_rule_qualification_matrix.py"])
    run("detection fixture generation", [sys.executable, "scripts/generate_detection_fixture_manifest.py"])
    run("fixture safety validation", [sys.executable, "scripts/validate_detection_fixture_manifest.py"])
    run("22-rule synthetic detection adapters", [sys.executable, "scripts/run_synthetic_detection_adapters.py"])
    run("policy signing contract", [sys.executable, "-m", "pytest", "tests/policy_signing/test_t7_signed_policy.py", "-q"])
    run("TypeScript policy contract", [sys.executable, "-m", "pytest", "tests/typescript/test_06_typescript_policy.py", "-q"])

    summary = {
        "schema": "aegis.rules-22-run-summary.v1",
        "mode": "synthetic_observe_only",
        "prevention_gate": "closed",
        "host_effect_capable": False,
        "rules_source": "configs/Rules.json",
        "expected_rule_count": 22,
        "failures": failures,
        "log": str(log_path),
    }
    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    log(f"SUMMARY={json.dumps(summary, separators=(',', ':'))}")
    try:
        LOCK.unlink()
    except FileNotFoundError:
        pass
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
