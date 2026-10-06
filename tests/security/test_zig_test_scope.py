"""TEST-SCOPE-085 + SCOPE-101: every unit test executes in `zig build test`.

Three silent-death incidents (policy_signing, federation_tcp,
federation_rust_tls — tests existed for months without ever
executing) proved the failure mode: `all_tests.zig` is the only
runner CI invokes, and nothing checked that a test file was reachable
from it.

SCOPE-101 correction: reachability was the WRONG property. A binary
scan (test-name strings in the built test.exe) proved ~175 tests dead
across 15 non-exempt files that were all "reachable" by transitive
@import closure — including every pre-existing test in
pipeline/event_queue.zig. Proven execution rule for this toolchain:
a file's tests execute with a DIRECT import edge in all_tests.zig or
a tests/ wrapper whose `comptime { _ = @import(...); }` forces
analysis; transitive-only reliance is silent death (direct wiring of
event_queue newly executed 7 tests, red-green proven).

This pin therefore requires, for every test-bearing file under src/:
a direct edge, a comptime-wrapper edge, an OUT_OF_UNIT scope below,
or a SCOPE101_BASELINE grandfather entry (transitional: files whose
execution today relies on incidental paths — migrate to a direct edge
when touched, then drop the entry). New files MUST take a direct edge
(or wrapper); the pin fails otherwise. Scopes:
  integration — operator harnesses (core-tools step), never unit-fast
  proof        — proof CLIs, same standing as integration
  bench        — real I/O + throughput floors (timing-sensitive)
  specimen     — design reference, intentionally uncompiled
  quarantine   — test-harness orchestrators, never production
  orphan       — legacy entry, additive-first (do not wire blindly)
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"

# Explicit scope per out-of-unit file. Every other test-bearing file
# under src/ must be reachable from all_tests.zig.
OUT_OF_UNIT: dict[str, str] = {
    # Integration harnesses (operator-run, core-tools step).
    "src/tests/integration/correlation_integration.zig": "integration",
    "src/tests/integration/detection_integration.zig": "integration",
    "src/tests/integration/fault_injection_integration.zig": "integration",
    "src/tests/integration/flow_integration.zig": "integration",
    "src/tests/integration/forensics_integration.zig": "integration",
    "src/tests/integration/golden_path_e3.zig": "integration",
    "src/tests/integration/hids_integration.zig": "integration",
    "src/tests/integration/ips_canary_integration.zig": "integration",
    "src/tests/integration/ips_simulation_integration.zig": "integration",
    "src/tests/integration/nose_integration.zig": "integration",
    "src/tests/integration/policy_integration.zig": "integration",
    "src/tests/integration/policy_plane_integration.zig": "integration",
    "src/tests/integration/rag_integration.zig": "integration",
    "src/tests/integration/release_engineering_integration.zig": "integration",
    "src/tests/integration/replay_integration.zig": "integration",
    "src/tests/integration/threat_intel_integration.zig": "integration",
    "src/tests/integration/xdr_harden_integration.zig": "integration",
    "src/tests/integration/brain_integration.zig": "integration",
    "src/tests/integration/concurrency_harden_integration.zig": "integration",
    "src/tests/integration/e2e_harness_integration.zig": "integration",
    "src/tests/integration/performance_integration.zig": "integration",
    "src/tests/integration/rust_pep_integration.zig": "integration",
    # Proof CLIs (same standing as integration).
    "src/tests/proofs/audit_trail_proof.zig": "proof",
    "src/tests/proofs/correlation_proof.zig": "proof",
    "src/tests/proofs/detection_fabric_proof.zig": "proof",
    "src/tests/proofs/flow_state_proof.zig": "proof",
    "src/tests/proofs/forensic_replay_proof.zig": "proof",
    "src/tests/proofs/health_monitoring_proof.zig": "proof",
    "src/tests/proofs/intelligence_proof.zig": "proof",
    "src/tests/proofs/pep_enforcement_proof.zig": "proof",
    "src/tests/proofs/policy_plane_proof.zig": "proof",
    "src/tests/proofs/siem_integration_proof.zig": "proof",
    "src/tests/proofs/telemetry_export_proof.zig": "proof",
    "src/tests/proofs/brain_proof.zig": "proof",
    "src/tests/proofs/compliance_proof.zig": "proof",
    "src/tests/proofs/config_reload_proof.zig": "proof",
    "src/tests/proofs/documentation_proof.zig": "proof",
    "src/tests/proofs/final_integration_proof.zig": "proof",
    "src/tests/proofs/performance_tuning_proof.zig": "proof",
    # Real TCP + throughput floors (timing-sensitive, operator harness).
    # NOTE: federation_bench is REACHED via cli_imports (bench CLI) —
    # no entry needed while that import stands.
    # Design reference, intentionally uncompiled (REL-SPEC-050 pattern).
    "src/federation/federation.zig": "specimen",
    "src/reliability/reliability.zig": "specimen",
    # Test-harness orchestrators, never production.
    "src/policy/dispatcher.zig": "quarantine",
    "src/policy/dispatcher_phase_b.zig": "quarantine",
    "src/reliability/lifecycle.zig": "quarantine",
}

VALID_SCOPES = {"integration", "proof", "specimen", "quarantine"}


def _imports_of(path: Path) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    out: set[str] = set()
    for m in re.finditer(r'@import\("([^"]+)"\)', text):
        target = m.group(1)
        if target.endswith(".zig") and not target.startswith("std"):
            resolved = (path.parent / target).resolve()
            try:
                out.add(str(resolved.relative_to(REPO_ROOT)).replace("\\", "/"))
            except ValueError:
                pass
    return out


def _has_tests(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    code = "\n".join(line.split("//", 1)[0] for line in text.splitlines())
    return re.search(r"(^|\s)test\s+\"", code) is not None


def _direct_edges() -> set[str]:
    """Files imported directly by src/all_tests.zig.

    SCOPE-101: this is the only statically checkable edge proven to
    execute a file's tests (binary-scan evidence). Transitive closure
    is NOT sufficient — event_queue.zig proved that live.
    """
    return _imports_of(SRC / "all_tests.zig")


def _wrapper_edges() -> set[str]:
    """Files pulled by a tests/ wrapper's `comptime { _ = @import(...); }`.

    The comptime block forces full analysis (proven by every wrapper's
    real-module tests executing). Matched on the exact established
    shape only — unconventional wrappers don't count.
    """
    covered: set[str] = set()
    for path in sorted((SRC / "tests").rglob("*.zig")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        code = "\n".join(line.split("//", 1)[0] for line in text.splitlines())
        for m in re.finditer(
            r"comptime\s*\{\s*_ = @import\(\"([^\"]+\.zig)\"\)", code
        ):
            target = m.group(1)
            resolved = (path.parent / target).resolve()
            try:
                rel = str(resolved.relative_to(REPO_ROOT)).replace("\\", "/")
            except ValueError:
                continue
            if (REPO_ROOT / rel).is_file():
                covered.add(rel)
    return covered


# SCOPE-101 grandfather set: test-bearing files with NEITHER a direct
# edge NOR a comptime-wrapper edge as of HEAD a86911e. Their tests may
# or may not execute today (incidental paths); each entry migrates out
# by gaining a direct edge (proven) — never by deleting tests. This
# set is FROZEN: it may only shrink.
SCOPE101_BASELINE: set[str] = {
    "src/core/authority_review.zig",
    "src/core/brain_engine.zig",
    "src/core/canary_progression.zig",
    "src/core/compliance_reporter.zig",
    "src/core/concurrency_harden.zig",
    "src/core/contract_freeze.zig",
    "src/core/e2e_harness.zig",
    "src/core/fabric_accounting.zig",
    "src/core/integration_test.zig",
    "src/core/legacy_removal.zig",
    "src/core/nids_analyze.zig",
    "src/core/nids_capture.zig",
    "src/core/perf_benchmark.zig",
    "src/core/performance_harness.zig",
    "src/core/priority_queue.zig",
    "src/core/real_ips_path.zig",
    "src/core/rust_pep.zig",
    "src/tests/core/bisect_b.zig",
    "src/tests/core/core_configs.zig",
}


def _test_files() -> list[str]:
    out = []
    for p in sorted((REPO_ROOT / "src").rglob("*.zig")):
        if p.suffixes == [".zig", ".scaffold"] or p.name.endswith(".scaffold"):
            continue
        rel = str(p.relative_to(REPO_ROOT)).replace("\\", "/")
        if _has_tests(p):
            out.append(rel)
    return out


def test_registry_scopes_are_valid():
    for rel, scope in OUT_OF_UNIT.items():
        assert scope in VALID_SCOPES, f"{rel}: unknown scope {scope!r}"
        assert (REPO_ROOT / rel).is_file(), f"registry points at missing file: {rel}"


def _covered() -> set[str]:
    """Files with a proven execution edge: direct or comptime-wrapper."""
    return _direct_edges() | _wrapper_edges()


def test_out_of_unit_files_stay_out():
    covered = _covered()
    leaked = [r for r in OUT_OF_UNIT if r in covered]
    assert not leaked, (
        "out-of-unit files gained an execution edge (silent promotion — "
        f"update the registry consciously): {leaked}"
    )


def test_every_other_test_file_is_covered():
    covered = _covered()
    missing = [
        r for r in _test_files()
        if r not in covered and r not in OUT_OF_UNIT
        and r not in SCOPE101_BASELINE and r != "src/all_tests.zig"
    ]
    assert not missing, (
        "test-bearing files without a proven execution edge (silent death — "
        f"wire them directly or scope them): {missing}"
    )


def test_baseline_entries_are_still_uncovered():
    # A baseline entry that gains coverage must leave the set: stale
    # entries hide the migration and rot the ratchet.
    covered = _covered()
    stale = sorted(r for r in SCOPE101_BASELINE if r in covered or r in OUT_OF_UNIT)
    assert not stale, (
        f"baseline entries already covered, drop them: {stale}"
    )
    for rel in SCOPE101_BASELINE:
        assert (REPO_ROOT / rel).is_file(), f"baseline points at missing file: {rel}"


def test_cli_imports_is_wired_for_compile_coverage():
    # The 16 CLI mains carry no tests but must not rot: cli_imports
    # exists precisely for compile coverage, so it must be reachable.
    assert "src/tests/cli_imports.zig" in _covered(), (
        "cli_imports.zig is not reachable: 16 CLI tools compile unchecked"
    )
