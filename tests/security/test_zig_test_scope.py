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
    # SCOPE-102: debug-bisect aggregator — its comptime imports pull
    # exempt integration/proof/bench scopes into analysis, so wiring it
    # would silently execute out-of-unit suites. Never production.
    "src/tests/core/bisect_b.zig": "quarantine",
    # SCOPE-102 batch 2: operator-run harnesses, never unit-fast.
    "src/core/e2e_harness.zig": "integration",
    "src/core/integration_test.zig": "integration",
    # SCOPE-102 batch 2: real I/O + throughput floors (timing-sensitive,
    # PERF-FLAKE class) — operator harnesses, not unit gates.
    "src/core/perf_benchmark.zig": "bench",
    "src/core/performance_harness.zig": "bench",
}

VALID_SCOPES = {"integration", "proof", "bench", "specimen", "quarantine"}


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


# ---------------------------------------------------------------------------
# DEADCODE-QUARANTINE (2026-10-19): build-root import closure.
#
# Six files are the only entry points any build step compiles (zig build:
# main.zig; zig build test: all_tests.zig; fuzz: fuzz_entry.zig; tool
# binaries: perf_bench_main.zig + integration_test_main.zig; service:
# daemon.zig). A src/*.zig file unreachable from ALL of them is dead code:
# never compiled, never executed, its tests silent-dead (the SCOPE-101
# failure class). The 35 files below were verified unreachable at ba7d926
# (75 production / 244 all-roots / 35 dead; AEGIS-DEEP-SCAN-REPORT.md §3).
#
# This pin IS the quarantine mechanism:
#   - a registered file must stay dead (wiring it into production or a
#     test root is a conscious promotion — drop the entry in the same
#     patch, updating OUT_OF_UNIT above when the file is test-bearing);
#   - a dead file must be registered (nothing rots silently).
# It cannot silently shrink or grow.
# ---------------------------------------------------------------------------

BUILD_ROOTS = frozenset({
    "src/main.zig",
    "src/daemon.zig",
    "src/all_tests.zig",
    "src/fuzz_entry.zig",
    "src/perf_bench_main.zig",
    "src/integration_test_main.zig",
})

QUARANTINED_UNREACHABLE = frozenset({
    # Non-test modules with no importer anywhere (headers state their
    # status; four protect reviewed design intent — see test_forbidden_edges).
    "src/capture/flow_types.zig",
    "src/capture/npcap_test_live.zig",
    "src/federation/federation.zig",
    "src/policy/dispatcher.zig",
    "src/policy/dispatcher_phase_b.zig",
    "src/reliability/lifecycle.zig",
    "src/reliability/reliability.zig",
    # Operator harnesses (core-tools step compiles only perf_bench and
    # integration_test mains — these facades are wired nowhere).
    "src/tests/integration/correlation_integration.zig",
    "src/tests/integration/detection_integration.zig",
    "src/tests/integration/fault_injection_integration.zig",
    "src/tests/integration/flow_integration.zig",
    "src/tests/integration/forensics_integration.zig",
    "src/tests/integration/golden_path_e3.zig",
    "src/tests/integration/hids_integration.zig",
    "src/tests/integration/ips_canary_integration.zig",
    "src/tests/integration/ips_simulation_integration.zig",
    "src/tests/integration/nose_integration.zig",
    "src/tests/integration/policy_integration.zig",
    "src/tests/integration/policy_plane_integration.zig",
    "src/tests/integration/rag_integration.zig",
    "src/tests/integration/release_engineering_integration.zig",
    "src/tests/integration/replay_integration.zig",
    "src/tests/integration/threat_intel_integration.zig",
    "src/tests/integration/xdr_harden_integration.zig",
    # Proof CLIs (same standing as integration).
    "src/tests/proofs/audit_trail_proof.zig",
    "src/tests/proofs/correlation_proof.zig",
    "src/tests/proofs/detection_fabric_proof.zig",
    "src/tests/proofs/flow_state_proof.zig",
    "src/tests/proofs/forensic_replay_proof.zig",
    "src/tests/proofs/health_monitoring_proof.zig",
    "src/tests/proofs/intelligence_proof.zig",
    "src/tests/proofs/pep_enforcement_proof.zig",
    "src/tests/proofs/policy_plane_proof.zig",
    "src/tests/proofs/siem_integration_proof.zig",
    "src/tests/proofs/telemetry_export_proof.zig",
})


def _all_src_zig_files() -> set[str]:
    out: set[str] = set()
    for p in (REPO_ROOT / "src").rglob("*.zig"):
        if p.name.endswith(".scaffold"):
            continue
        out.add(str(p.relative_to(REPO_ROOT)).replace("\\", "/"))
    return out


def _root_closure() -> set[str]:
    """Transitive @import closure of the six build roots."""
    seen: set[str] = set()
    queue = list(BUILD_ROOTS)
    while queue:
        rel = queue.pop()
        if rel in seen:
            continue
        seen.add(rel)
        for nxt in _imports_of(REPO_ROOT / rel):
            if nxt not in seen:
                queue.append(nxt)
    return seen


def test_build_root_closure_equals_the_quarantine_registry():
    universe = _all_src_zig_files()
    for root in BUILD_ROOTS:
        assert (REPO_ROOT / root).is_file(), f"build root missing: {root}"

    missing = sorted(QUARANTINED_UNREACHABLE - universe)
    assert not missing, (
        "quarantined files no longer exist — delete the registry entry "
        f"together with the file: {missing}"
    )

    reachable = _root_closure()
    promoted = sorted(QUARANTINED_UNREACHABLE & reachable)
    assert not promoted, (
        "quarantined files gained a build-root edge (silent revival) — "
        f"drop the entry in the same patch as the wiring: {promoted}"
    )

    unregistered = sorted(universe - reachable - QUARANTINED_UNREACHABLE)
    assert not unregistered, (
        "src/*.zig files unreachable from every build root are unregistered "
        f"dead code — wire them or register them here: {unregistered}"
    )
