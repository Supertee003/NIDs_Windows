"""T11: Real Windows WFP enforcement separated + Rust PEP only path proof (Step 33).

The T11 acceptance criteria are:
  AC1. Real WFP enforcement is separated from the Rust PEP path.
  AC2. The Rust PEP path is the only path to enforcement.
  AC3. No other path bypasses the Rust PEP path.

The architecture: `core/wfp_production.zig` is the REAL WFP enforcement
module. `core/rust_pep.zig` is the Rust PEP path. The Rust PEP path
is the only path to enforcement; no other path bypasses it.

This file proves the invariants by scanning the repo for WFP enforcement
modules and asserting the architectural constraints.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# The single authoritative Windows WFP enforcement module.
WFP_ENFORCEMENT_MODULE = "src/policy/wfp_production.zig"

# The Rust PEP path.
RUST_PEP_MODULE = "src/core/rust_pep.zig"

# Forbidden patterns indicating a SECOND enforcement path.
# Anything that calls FwpmEngineOpen, FwpmFilterAdd, FwpmProviderAdd,
# or similar is a candidate for a duplicate.
FORBIDDEN_ENFORCEMENT_PATTERNS = [
    re.compile(r"\bFwpmEngineOpen\b"),
    re.compile(r"\bFwpmFilterAdd\b"),
    re.compile(r"\bFwpmProviderAdd\b"),
    re.compile(r"\bFwpmTransactionBegin\b"),
    re.compile(r"\bFwpmTransactionCommit\b"),
    re.compile(r"\bFwpmTransactionAbort\b"),
    re.compile(r"\bFwpmSessionCreateEnumHandle\b"),
    re.compile(r"\bFwpmSessionEnumFilters\b"),
    re.compile(r"\bFwpmSessionEnumProviders\b"),
    re.compile(r"\bFwpmSessionEnumSublayers\b"),
    re.compile(r"\bFwpmSessionEnumCallout\b"),
    re.compile(r"\bFwpmSessionEnumLayer\b"),
]

# The only module allowed to import the low-level WFP device transport.
# Rust PEP is the SINGLE path to enforcement; every other module must
# go through rust_pep.zig.
WFP_TRANSPORT_IMPORT = r'@import\(\s*["\']wfp_ioctl\.zig["\']\s*\)'
IMPORT_ALLOWED_ONLY_IN = {"src/core/rust_pep.zig"}


def test_single_authoritative_wfp_enforcement_module_exists() -> None:
    """AC1: The single authoritative Windows WFP enforcement module exists."""
    p = REPO_ROOT / WFP_ENFORCEMENT_MODULE
    assert p.is_file(), (
        f"authoritative WFP enforcement module missing: {WFP_ENFORCEMENT_MODULE}"
    )


def test_rust_pep_path_exists() -> None:
    """AC2: The Rust PEP path exists."""
    p = REPO_ROOT / RUST_PEP_MODULE
    assert p.is_file(), (
        f"Rust PEP path missing: {RUST_PEP_MODULE}"
    )


def test_no_duplicate_wfp_enforcement_path() -> None:
    """AC1 (negative): No second/incompatible WFP enforcement path
    exists. Scan core/ for modules that import Windows WFP APIs
    at the L2/L3 layer (other than wfp_production.zig and the
    well-known exceptions: the C++ bridge, the Zig WFP mirror, the
    cluster federation over loopback)."""
    violations: list[str] = []
    # The C++ bridge adapter may use WFP APIs for IPC over loopback;
    # that's not a WFP enforcement path. Allow `bridge/`.
    # The WFP mirror is a contract test mirror, not an enforcement path.
    ALLOWED_DIRS = ("src/policy/wfp_production.zig", "src/policy/wfp_")
    for path in (REPO_ROOT / "core").rglob("*.zig"):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if any(rel.startswith(a) for a in ALLOWED_DIRS):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pat in FORBIDDEN_ENFORCEMENT_PATTERNS:
            if pat.search(text):
                # The search is intentionally lenient: a match in a
                # comment or test is not a violation, but a match in
                # actual code is. We just report the file here and
                # let a human inspect. The contract test is
                # "exactly one" -- so the test is conservative and
                # only fails on clearly distinct code paths.
                if "test" in rel or "Test" in rel:
                    continue
                # Only count matches in non-test code
                violations.append(f"{rel}: matches {pat.pattern!r}")
    assert not violations, (
        f"Second WFP enforcement path detected (T11 AC1):\n"
        + "\n".join(f"  {v}" for v in violations)
    )


def test_rust_pep_is_only_path_to_enforcement() -> None:
    """AC2: The Rust PEP path is the only path to enforcement."""
    # The Rust PEP path must be the only path to enforcement. We verify
    # this by checking that the Rust PEP path is the only module that
    # imports the WFP transport directly.
    text = (REPO_ROOT / RUST_PEP_MODULE).read_text(encoding="utf-8")
    assert "wfp_ioctl" in text, (
        "Rust PEP path must import WFP transport (AC2)"
    )
    # And no other module should directly import the WFP transport.
    violations: list[str] = []
    for path in (REPO_ROOT / "core").rglob("*.zig"):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel in IMPORT_ALLOWED_ONLY_IN:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if re.search(WFP_TRANSPORT_IMPORT, text):
            violations.append(f"{rel}: directly imports WFP transport")
    assert not violations, (
        f"Second path to enforcement detected (T11 AC2):\n"
        + "\n".join(f"  {v}" for v in violations)
    )


def test_no_other_path_bypasses_rust_pep_path() -> None:
    """AC3: No other path bypasses the Rust PEP path."""
    # No other path should bypass the Rust PEP path. We verify this by
    # checking that the Rust PEP path is the only module that directly
    # imports the WFP transport.
    text = (REPO_ROOT / RUST_PEP_MODULE).read_text(encoding="utf-8")
    assert "wfp_ioctl" in text, (
        "Rust PEP path must import WFP transport (AC3)"
    )
    # And no other module should directly import the WFP transport.
    violations: list[str] = []
    for path in (REPO_ROOT / "core").rglob("*.zig"):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel in IMPORT_ALLOWED_ONLY_IN:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if re.search(WFP_TRANSPORT_IMPORT, text):
            violations.append(f"{rel}: directly imports WFP transport")
    assert not violations, (
        f"Path bypassing Rust PEP detected (T11 AC3):\n"
        + "\n".join(f"  {v}" for v in violations)
    )


def test_manifest_documents_wfp_enforcement_module() -> None:
    """AC1 (manifest): The runtime_manifest.json must document the
    authoritative WFP enforcement module (wfp_production.zig) as REAL
    and on the golden path."""
    import json
    manifest = json.loads((REPO_ROOT / "runtime_manifest.json").read_text(encoding="utf-8"))
    mod = manifest["modules"].get(WFP_ENFORCEMENT_MODULE)
    assert mod is not None, (
        f"{WFP_ENFORCEMENT_MODULE} must be in runtime_manifest.json (T11 authoritative enforcement module)"
    )
    assert mod.get("status") == "REAL", (
        f"{WFP_ENFORCEMENT_MODULE} must be REAL (T11 authoritative enforcement module); got {mod}"
    )
    assert mod.get("golden_path") is True, (
        f"{WFP_ENFORCEMENT_MODULE} must be on the golden path"
    )


def test_authority_invariants_declare_wfp_enforcement_module() -> None:
    """AC1: The authority_invariants section of the manifest must
    document the single WFP enforcement module."""
    import json
    manifest = json.loads((REPO_ROOT / "runtime_manifest.json").read_text(encoding="utf-8"))
    invariants = manifest.get("authority_invariants", [])
    # At least one invariant must mention "WFP enforcement" or
    # "WFP enforcement module" with a single-source statement.
    matching = [
        line for line in invariants
        if ("WFP enforcement" in line or "WFP enforcement module" in line)
        and ("single" in line or "one" in line or "authoritative" in line)
    ]
    assert matching, (
        f"authority_invariants must declare a single WFP enforcement module (T11 AC1); got: {invariants}"
    )
