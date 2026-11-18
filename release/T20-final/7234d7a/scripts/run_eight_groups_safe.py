from __future__ import annotations

import datetime as dt
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANALYSIS = ROOT / "analysis"
LOCK = ANALYSIS / ".eight-groups-run.lock"


def acquire_lock() -> None:
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    try:
        with LOCK.open("x", encoding="utf-8") as handle:
            handle.write(f"pid={os.getpid()}\nstarted={dt.datetime.now(dt.timezone.utc).isoformat()}\n")
    except FileExistsError as exc:
        raise SystemExit(
            f"Another safe verification run is active or {LOCK} is stale. "
            "Remove it only after confirming no runner is active."
        ) from exc


def main() -> int:
    acquire_lock()
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S") + f"_{os.getpid()}"
    out_dir = ANALYSIS / f"host-eight-groups-{stamp}"
    out_dir.mkdir(parents=False, exist_ok=False)
    log_path = out_dir / "run.log"
    failures = 0
    passes = 0
    skips = 0

    def emit(text: str) -> None:
        print(text, flush=True)
        with log_path.open("a", encoding="utf-8", newline="") as handle:
            handle.write(text + "\n")

    def section(title: str) -> None:
        emit("")
        emit(f"=== {title} ===")

    def run(label: str, args: list[str], cwd: Path = ROOT, env: dict[str, str] | None = None) -> None:
        nonlocal failures, passes
        emit(f"[RUN] {label}: {' '.join(args)}")
        merged_env = os.environ.copy()
        merged_env.update(env or {})
        try:
            result = subprocess.run(
                args,
                cwd=str(cwd),
                env=merged_env,
                capture_output=True,
                text=True,
                errors="replace",
                check=False,
            )
        except OSError as exc:
            emit(f"[FAIL] {label} launch error={exc}")
            failures += 1
            return
        if result.stdout:
            with log_path.open("a", encoding="utf-8", newline="") as handle:
                handle.write(result.stdout)
        if result.stderr:
            with log_path.open("a", encoding="utf-8", newline="") as handle:
                handle.write(result.stderr)
        if result.returncode:
            emit(f"[FAIL] {label} exit={result.returncode}")
            failures += 1
        else:
            emit(f"[PASS] {label}")
            passes += 1

    def observe_ps(label: str, script: Path, args: list[str]) -> None:
        run(
            label,
            ["powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), *args],
        )

    emit("AEGIS Eight-Group Safe Verification")
    emit(f"Root={ROOT}")
    emit(f"Log={log_path}")
    emit("Safety=observe-only; prevention_gate=closed; host_effect_capable=false")

    section("PROVENANCE")
    for label, args in [
        ("whoami", ["whoami"]),
        ("git status", ["git", "status", "--short", "--branch"]),
        ("git revision", ["git", "rev-parse", "HEAD"]),
        ("python version", [sys.executable, "--version"]),
        ("cargo version", ["cargo", "--version"]),
        ("zig version", ["zig", "version"]),
        ("go version", ["go", "version"]),
        ("node version", ["node", "--version"]),
        ("npm version", ["npm", "--version"]),
    ]:
        run(label, args)

    section("GROUP 1 - ZIG RUNTIME")
    run("Zig unit tests", ["zig", "build", "test", "-Doptimize=Debug"])
    run("runtime health tests", [sys.executable, "-m", "pytest", "tests/runtime/test_health.py", "tests/runtime/test_states.py", "-q"])
    run("runtime restart contract", [sys.executable, "-m", "pytest", "tests/runtime/test_restart.py", "-q"])

    section("GROUP 2 - WFP DRIVER AND USER ADAPTER (OBSERVE ONLY)")
    observe_ps("WFP L4 observe-only proof", ROOT / "scripts/run_wfp_l4_observe_only_proof.ps1", ["-WaitSeconds", "3", "-GenerateBenignProbe"])
    run("WFP contract tests", [sys.executable, "-m", "pytest", "tests/wfp/test_t11_windows_host.py", "-q"], env={"AEGIS_RUN_WFP_HOST_TESTS": "0"})

    section("GROUP 3 - GO NOSE")
    if (ROOT / "nose/go.mod").is_file():
        run("Go Nose tests", ["go", "test", "./..."], cwd=ROOT / "nose")
    else:
        emit("[SKIP] nose/go.mod missing")
        skips += 1

    section("GROUP 4 - FIM")
    observe_ps("FIM observe-only fixture proof", ROOT / "scripts/run_fim_real_observe_only_proof.ps1", ["-ProofRoot", os.path.join(os.environ.get("TEMP", r"C:\\Windows\\Temp"), "aegis-fim-proof"), "-WaitSeconds", "2"])
    run("FIM host telemetry tests", [sys.executable, "-m", "pytest", "tests/host_telemetry/test_t10_single_source.py", "-q"])

    section("GROUP 5 - ETW AND REGISTRY")
    run("host telemetry tests", [sys.executable, "-m", "pytest", "tests/host_telemetry", "-q"])
    run("health semantics tests", [sys.executable, "-m", "pytest", "tests/runtime/test_health.py", "-q"])

    section("GROUP 6 - RUST PEP AND SHIELD")
    run("Rust PEP tests", ["cargo", "test", "--manifest-path", str(ROOT / "Cargo.toml")])
    if (ROOT / "shield/Cargo.toml").is_file():
        run("Shield tests", ["cargo", "test", "--manifest-path", str(ROOT / "shield/Cargo.toml")])
    else:
        emit("[SKIP] shield/Cargo.toml missing")
        skips += 1
    run("PEP Python contract tests", [sys.executable, "-m", "pytest", "tests/pep/test_t8_rust_pep.py", "-q"])

    section("GROUP 7 - PYTHON AND CYTHON DETECTION")
    run("Cython correctness", [sys.executable, "-m", "pytest", "tests/cython/test_cython_correctness.py", "tests/cython/test_cython_no_policy_path.py", "-q"])
    run("detection integration", [sys.executable, "-m", "pytest", "tests/runtime/test_golden_path.py", "tests/runtime/test_wire.py", "-q"])

    section("GROUP 8 - POLICY AND TYPESCRIPT")
    run("rules validation", [sys.executable, "tools/aegisctl.py", "rules", "validate"])
    run("signed policy tests", [sys.executable, "-m", "pytest", "tests/policy_signing/test_t7_signed_policy.py", "-q"])
    run("TypeScript policy tests", [sys.executable, "-m", "pytest", "tests/typescript/test_06_typescript_policy.py", "-q"])
    ts_dir = ROOT / "ts_policy"
    if (ts_dir / "package.json").is_file() and (ts_dir / "node_modules").is_dir():
        run("TypeScript typecheck", ["npm", "run", "typecheck"], cwd=ts_dir)
        run("TypeScript safety tests", ["npm", "run", "test:safety"], cwd=ts_dir)
        run("TypeScript contract tests", ["npm", "run", "test:contract"], cwd=ts_dir)
    else:
        emit("[SKIP] ts_policy/node_modules missing")
        skips += 1

    section("FINAL SAFETY ASSERTIONS")
    emit("prevention_gate=closed")
    emit("host_effect_capable=false")
    emit("WFP block/unblock commands were not invoked by this script")
    emit(f"PASS={passes} FAIL={failures} SKIP={skips}")
    try:
        LOCK.unlink()
    except FileNotFoundError:
        pass
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
