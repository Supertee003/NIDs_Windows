"""Final regression over the full subsystem matrix (T20 AC1, Step 60).

Runs the 16 subsystem gates from the AEGIS verification plan and tallies
the result to docs/gates/T20_final_regression.{json,md}:

  unit / integration / contracts / windows-host / driver / fault /
  security / performance / tls / federation / installer / upgrade /
  rollback / replay / ips / xdr

A regression FAIL on any produced-path subsystem (rc != 0) blocks the
release-candidate declaration. Unaudited-partial subsystems (driver,
installer) are reported with their known limitation.

Usage:
    python tools/final_regression.py [--pass]   # --pass: assert all rc==0
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "gates" / "T20_final_regression.json"
OUT_MD = REPO / "docs" / "gates" / "T20_final_regression.md"

# subsystem -> (zig targets, pytest dirs, tool runs)
SUBSYSTEMS: dict[str, dict] = {
    "unit":            {"zig": ["core/event_queue.zig", "core/priority_queue.zig",
                                "core/flow_engine.zig", "core/canonical_event.zig"],
                        "pytest": [], "tools": []},
    "integration":     {"zig": ["core/dispatcher.zig", "core/event_fabric.zig",
                                "core/runtime_spine.zig"],
                        "pytest": ["tests/runtime"], "tools": []},
    "contracts":       {"zig": [], "pytest": ["tests/adapters",
                                              "tests/cython"], "tools": []},
    "windows-host":    {"zig": ["core/windows_adapters.zig", "core/wfp_ioctl.zig"],
                        "pytest": ["tests/host_telemetry"],
                        "tools": [(["go", "test", "./..."], "nose go test",
                                   "nose")]},
    "driver":          {"zig": ["core/wfp_production.zig"],
                        "pytest": ["tests/wfp"],
                        "tools": [(["python", "tools/config_validator.py",
                                    "--config", "config/Rules.json"],
                                   "policy validator", "")]},
    "fault":           {"zig": ["core/fault_matrix.zig", "core/fault_injection.zig",
                                "core/fault_injection_integration.zig",
                                "core/reliability.zig"],
                        "pytest": ["tests/reliability"], "tools": []},
    "security":        {"zig": ["core/decision_trace.zig", "core/shadow_decision.zig",
                                "core/replayable_security.zig",
                                "core/authority_review.zig"],
                        "pytest": ["tests/security", "tests/pep",
                                   "tests/policy_signing"], "tools": []},
    "performance":     {"zig": ["core/perf_benchmark.zig",
                                "core/performance_harness.zig",
                                "core/performance_integration.zig",
                                "core/performance_tuning_proof.zig"],
                        "pytest": [], "tools": []},
    "tls":             {"zig": [("core/federation_tls.zig", True),
                                "core/federation_codec.zig"],
                        "pytest": [], "tools": []},
    "federation":      {"zig": ["core/cluster_coord.zig",
                                ("core/federation_bench.zig", True)],
                        "pytest": ["tests/federation"], "tools": []},
    "installer":       {"zig": ["core/release_engineering.zig",
                                "core/release_engineering_integration.zig",
                                "core/release_provenance.zig"],
                        "pytest": ["tests/release"],
                        "tools": [(["python", "tools/installer.py", "--generate"],
                                   "installer package", "")]},
    "upgrade":         {"zig": [], "pytest": ["tests/release"],
                        "tools": [(["python", "tools/upgrade_rollback.py",
                                    "report", "--json"], "config snapshot", "")]},
    "rollback":        {"zig": [], "pytest": ["tests/release"],
                        "tools": [(["python", "tools/upgrade_rollback.py",
                                    "report", "--json"], "rollback report", "")]},
    "replay":          {"zig": ["core/replay_engine.zig",
                                "core/replayable_security.zig"],
                        "pytest": ["tests/security"], "tools": []},
    "ips":             {"zig": ["core/real_ips_path.zig", "core/ips_canary_order.zig",
                                "core/policy_engine.zig"],
                        "pytest": ["tests/ips"], "tools": []},
    "xdr":             {"zig": ["core/xdr_incident_fabric.zig"],
                        "pytest": ["tests/ips", "tests/test_golden_path.py"],
                        "tools": []},
}

KNOWN_PARTIAL = ["driver", "installer", "upgrade", "rollback"]


def run(cmd: list[str], timeout: int = 900, cwd: str | None = None) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           cwd=str(REPO if cwd is None else REPO / cwd),
                           env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                           errors="replace")
        return r.returncode, (r.stdout or r.stderr).strip().splitlines()[-1:][0][:160]
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"
    except OSError as e:
        return -2, str(e)


def run_subsystem(name: str, spec: dict) -> dict:
    details: list[dict] = []
    for z in spec["zig"]:
        libc = False
        if isinstance(z, tuple):
            z, libc = z
        zpath = REPO / z
        if not zpath.exists():
            details.append({"target": z, "type": "zig", "rc": -3,
                            "note": "file missing"})
            continue
        rc, note = run(["zig", "test", z, "-lc"] if libc else ["zig", "test", z])
        details.append({"target": z, "type": "zig", "rc": rc, "note": note})
    for d in spec["pytest"]:
        rc, note = run(["python", "-m", "pytest", d, "-q"])
        details.append({"target": d, "type": "pytest", "rc": rc, "note": note})
    for cmd, label, workdir in spec["tools"]:
        rc, note = run(cmd, cwd=workdir or "")
        details.append({"target": label, "type": "tool", "rc": rc, "note": note})
    fails = [d for d in details if d["rc"] != 0]
    return {"result": "FAIL" if fails else "PASS", "runs": len(details),
            "failures": len(fails), "details": details}


def main() -> int:
    results = {}
    for name, spec in SUBSYSTEMS.items():
        results[name] = run_subsystem(name, spec)

    rolling = {"pass": 0, "fail": 0, "full_suite": None}
    for name, r in results.items():
        if r["result"] == "PASS":
            rolling["pass"] += 1
        else:
            rolling["fail"] += 1

    full_rc, _ = run(["python", "-m", "pytest", "tests", "-q"], 1200)
    rolling["full_suite"] = "PASS" if full_rc == 0 else "FAIL"

    report = {
        "ticket": "T20 AC1", "step": 60,
        "generated": datetime.now(timezone.utc).isoformat(),
        "subsystems": results,
        "tally": rolling,
        "known_partial_subsystems": KNOWN_PARTIAL,
        "declaration": ("REG NEG PASS" if rolling["full_suite"] == "PASS"
                        and rolling["fail"] == 0 else "REG NEG FAIL"),
    }
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    OUT_MD.write_text(render(report), encoding="utf-8")
    print("%s (pass=%d fail=%d full_suite=%s)"
          % (report["declaration"], rolling["pass"], rolling["fail"],
             rolling["full_suite"]))
    for name, r in results.items():
        if r["result"] == "FAIL":
            print("  FAIL %s: %s" % (name, r["details"]))
    return 0 if report["declaration"] == "REG NEG PASS" else 1


def render(rep: dict) -> str:
    lines = ["# AEGIS Final Regression (T20 AC1, Step 60)",
             "", "- Generated: %s" % rep["generated"],
             "- Full pytest suite: **%s**" % rep["tally"]["full_suite"],
             "- Subsystems: %d pass / %d fail / %d total"
             % (rep["tally"]["pass"], rep["tally"]["fail"],
                len(rep["subsystems"])),
             "- Known partial (unaudited): %s" % ", ".join(
                 rep["known_partial_subsystems"]),
             "- [ ] Gap: subsystem FAIL" if rep["tally"]["fail"] else
             "- **All produced-path subsystems PASS**",
             "", "| subsystem | result | runs | failures |",
             "|---|---|---|---|"]
    for name, r in rep["subsystems"].items():
        lines.append("| %s | %s | %d | %d |" % (name, r["result"], r["runs"],
                                                r["failures"]))
    lines.append("")
    for name, r in rep["subsystems"].items():
        if r["result"] == "FAIL":
            lines.append("Failing detail - %s:" % name)
            for d in r["details"]:
                if d["rc"] != 0:
                    lines.append("- %s %s rc=%d %s"
                                 % (d["type"], d["target"], d["rc"],
                                    d["note"]))
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())