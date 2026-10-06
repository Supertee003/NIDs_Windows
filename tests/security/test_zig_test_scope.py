"""TEST-SCOPE-085: every unit test executes in `zig build test`.

Three silent-death incidents (policy_signing, federation_tcp,
federation_rust_tls — tests existed for months without ever
executing) proved the failure mode: `all_tests.zig` is the only
runner CI invokes, and nothing checked that a test file was reachable
from it. This pin computes the transitive @import closure from
src/all_tests.zig and asserts every test-bearing file is either
inside it or explicitly scoped below.

Moving a file OUT of the unit binary (or adding tests to an
out-of-scope file) fails here — consciously, reviewed, with the
registry updated in the same patch. Scopes:
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


def _unit_closure() -> set[str]:
    seen: set[str] = set()
    stack = ["src/all_tests.zig"]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for nxt in _imports_of(REPO_ROOT / cur):
            if nxt not in seen:
                stack.append(nxt)
    return seen


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


def test_out_of_unit_files_stay_out():
    closure = _unit_closure()
    leaked = [r for r in OUT_OF_UNIT if r in closure]
    assert not leaked, (
        "out-of-unit files became reachable (silent promotion — "
        f"update the registry consciously): {leaked}"
    )


def test_every_other_test_file_is_reachable():
    closure = _unit_closure()
    missing = [r for r in _test_files() if r not in closure and r not in OUT_OF_UNIT]
    assert not missing, (
        "test-bearing files unreachable from all_tests.zig (silent death — "
        f"wire them or scope them): {missing}"
    )


def test_cli_imports_is_wired_for_compile_coverage():
    # The 16 CLI mains carry no tests but must not rot: cli_imports
    # exists precisely for compile coverage, so it must be reachable.
    assert "src/tests/cli_imports.zig" in _unit_closure(), (
        "cli_imports.zig is not reachable: 16 CLI tools compile unchecked"
    )
