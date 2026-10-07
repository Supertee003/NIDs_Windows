#!/usr/bin/env python3
"""DEPLOY-117: fresh-deploy closure (STEP 50).

Chains only canonical in-repo tools, fail-closed, additive only:

  1. preflight : python tools/release_engineering.py --verify   (read-only)
  2. validate  : python tools/config_validator.py --config configs/runtime.json (read-only;
           runtime.json is the system config matching configs/schema.json;
           detection rules in configs/Rules.json are validated separately
           by the ConfigStore hot-reload path)
  3. snapshot  : python tools/upgrade_rollback.py snapshot --json (writes logs/snapshots)
  4. package   : python tools/installer.py --package --output <out> (needs makensis; fail-closed without it)
  5. report    : python tools/upgrade_rollback.py report --json (read-only)

Modes:
  --plan   run read-only steps live, mark mutating steps DEFERRED, write
           nothing, exit 0 on healthy read-only steps. Safe for CI/tests.
  (live)   run all five in order; first nonzero return code aborts the
           chain and is returned. The final record (steps + timings) goes
           to stdout as JSON with --json; this tool never writes files
           itself (operator redirects stdout for a handoff bundle).

Residual (not closed here): installer NSI body stays a static template;
per-artifact File lines are not yet manifest-driven (file_directive()
exists but is unused by generate_nsi).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable


def run_step(name: str, cmd: list[str], mutate: bool, plan: bool) -> dict:
    """Run one step, or record it DEFERRED under --plan when it mutates."""
    if plan and mutate:
        return {"name": name, "cmd": cmd, "status": "DEFERRED",
                "reason": "mutating step skipped under --plan", "rc": None,
                "ms": 0}
    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True,
                              text=True, timeout=600)
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:  # fail-closed on launch failure
        return {"name": name, "cmd": cmd, "status": "ERROR",
                "reason": str(exc), "rc": 3, "ms": 0}
    ms = int((time.monotonic() - start) * 1000)
    rec = {"name": name, "cmd": cmd,
           "status": "OK" if rc == 0 else "FAIL", "rc": rc, "ms": ms}
    tail = (out.strip().splitlines()[-1:] or [""])[0][:200]
    if tail:
        rec["tail"] = tail
    if rc != 0 and err.strip():
        rec["stderr_tail"] = err.strip().splitlines()[-1][:200]
    return rec


STEPS = [
    ("preflight", [PY, "tools/release_engineering.py", "--verify"], False),
    ("validate", [PY, "tools/config_validator.py", "--config",
                  "configs/runtime.json"], False),
    ("snapshot", [PY, "tools/upgrade_rollback.py", "snapshot", "--json"], True),
    ("package", [PY, "tools/installer.py", "--package", "--output",
                 "aegis_setup.exe"], True),
    ("report", [PY, "tools/upgrade_rollback.py", "report", "--json"], False),
]


def main() -> int:
    ap = argparse.ArgumentParser(description="AEGIS fresh-deploy closure (STEP 50)")
    ap.add_argument("--plan", action="store_true",
                    help="run read-only steps only; defer mutating steps; write nothing")
    ap.add_argument("--json", action="store_true",
                    help="emit the final step record as JSON on stdout")
    args = ap.parse_args()

    steps = [run_step(name, cmd, mutate, args.plan)
             for name, cmd, mutate in STEPS]
    failed = next((s for s in steps if s["status"] in ("FAIL", "ERROR")), None)
    record = {"tool": "fresh_deploy", "mode": "plan" if args.plan else "live",
              "steps": steps,
              "ok": failed is None,
              "failed_step": failed["name"] if failed else None}
    if args.json:
        print(json.dumps(record, indent=2))
    else:
        for s in steps:
            print(f"[{s['status']}] {s['name']} rc={s['rc']} ms={s['ms']}")
        print("DEPLOY_PLAN_OK" if record["ok"] else
              f"DEPLOY_FAILED_AT={record['failed_step']}")
    return 0 if record["ok"] else (failed.get("rc") or 1)


if __name__ == "__main__":
    sys.exit(main())
