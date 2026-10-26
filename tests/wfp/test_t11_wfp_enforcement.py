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

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DRIVER_HEADER = REPO_ROOT / "drivers" / "wfp_callout" / "aegis_wfp.h"
DRIVER_SOURCE = REPO_ROOT / "drivers" / "wfp_callout" / "aegis_wfp.c"
DRIVER_CALLOUT = REPO_ROOT / "drivers" / "wfp_callout" / "aegis_wfp_callout.c"

# The single authoritative Windows WFP enforcement module.
WFP_ENFORCEMENT_MODULE = "src/policy/wfp_production.zig"

# The Rust PEP path.
RUST_PEP_MODULE = "rust-src/lib.rs"

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

# No Zig module may import the low-level WFP device transport. WFP access is
# an implementation detail of the Rust PEP, not a runtime-spine interface.
WFP_PRIVILEGED_CALL = re.compile(r'\bwfp_ioctl\.(?:block_ip|unblock_ip)\s*\(')


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
    exists. Scan src/ for modules that import Windows WFP APIs
    at the L2/L3 layer (other than wfp_production.zig and the
    well-known exceptions: the C++ bridge, the Zig WFP mirror, the
    cluster federation over loopback)."""
    violations: list[str] = []
    # The C++ bridge adapter may use WFP APIs for IPC over loopback;
    # that's not a WFP enforcement path. Allow `bridge/`.
    # The WFP mirror is a contract test mirror, not an enforcement path.
    ALLOWED_DIRS = ("src/policy/wfp_production.zig", "src/policy/wfp_")
    # TEST-001: the old `core/` tree was migrated to src/. Scanning a
    # non-existent directory made this negative control pass vacuously.
    for path in (REPO_ROOT / "src").rglob("*.zig"):
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
        "Second WFP enforcement path detected (T11 AC1):\n"
        + "\n".join(f"  {v}" for v in violations)
    )


def test_rust_pep_is_only_path_to_enforcement() -> None:
    """AC2: The Rust PEP path is the only path to enforcement."""
    # The Rust PEP is the only authority. Zig must not expose the transport.
    assert (REPO_ROOT / RUST_PEP_MODULE).is_file()
    violations: list[str] = []
    for path in (REPO_ROOT / "src").rglob("*.zig"):
        rel = path.relative_to(REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        if WFP_PRIVILEGED_CALL.search(text):
            violations.append(f"{rel}: directly calls privileged WFP transport")
    assert not violations, (
        "Second path to enforcement detected (T11 AC2):\n"
        + "\n".join(f"  {v}" for v in violations)
    )


def test_no_other_path_bypasses_rust_pep_path() -> None:
    """AC3: No other path bypasses the Rust PEP path."""
    # No Zig module may bypass the Rust PEP by importing the transport.
    violations: list[str] = []
    for path in (REPO_ROOT / "src").rglob("*.zig"):
        rel = path.relative_to(REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        if WFP_PRIVILEGED_CALL.search(text):
            violations.append(f"{rel}: directly calls privileged WFP transport")
    assert not violations, (
        "Path bypassing Rust PEP detected (T11 AC3):\n"
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


def test_driver_unblock_contract_matches_user_adapter() -> None:
    """The user adapter uses exact filter identity for cleanup."""
    header = DRIVER_HEADER.read_text(encoding="utf-8", errors="ignore")
    source = DRIVER_SOURCE.read_text(encoding="utf-8", errors="ignore")
    assert "#define IOCTL_AEGIS_UNBLOCK_FLOW" in header
    assert "case IOCTL_AEGIS_UNBLOCK_FLOW:" in source
    assert "AEGIS_WFP_FLOW_REQUEST" in header
    assert "AEGIS_WFP_FLOW_RESPONSE" in header
    assert "UINT64 filter_id" in header
    assert "aegis_wfp_ioctl_unblock_filter" in (
        (REPO_ROOT / "src" / "windows" / "wfp_ioctl.c").read_text(
            encoding="utf-8", errors="ignore"
        )
    )


def test_driver_rejects_unknown_flow_direction() -> None:
    """An unknown direction must never mint an outbound proof filter."""
    source = DRIVER_SOURCE.read_text(encoding="utf-8", errors="ignore")
    block = source.split("NTSTATUS AegisWfpBlockFlow(PIRP Irp) {", 1)[1].split(
        "NTSTATUS AegisWfpGetStats(PIRP Irp) {", 1
    )[0]
    assert block.count("if (request->direction > 1)") == 1
    assert "return STATUS_INVALID_PARAMETER;" in block


def test_driver_initializes_passive_level_proof_lock() -> None:
    """WFP management APIs require PASSIVE_LEVEL; a FAST_MUTEX is invalid."""
    source = DRIVER_SOURCE.read_text(encoding="utf-8", errors="ignore")
    header = DRIVER_HEADER.read_text(encoding="utf-8", errors="ignore")

    assert "KeInitializeMutex(&g_ProofLock, 0);" in source
    assert "g_ProofLockReady = TRUE;" in source
    assert "KeWaitForSingleObject(&g_ProofLock" in source
    assert "return status == STATUS_SUCCESS ? STATUS_SUCCESS : status;" in source
    assert "KeReleaseMutex(&g_ProofLock" in source
    assert "ExAcquireFastMutex" not in source
    assert "ExReleaseFastMutex" not in source
    assert "NTSTATUS AegisWfpCleanupProofFilters(void);" in header


def test_driver_lifecycle_prepares_after_register_and_cleans_before_unregister() -> None:
    """The proof provider and its persistent filters must have one owner."""
    source = DRIVER_SOURCE.read_text(encoding="utf-8", errors="ignore")

    entry = source.split("NTSTATUS DriverEntry", 1)[1].split(
        "// ====== Unload ======", 1
    )[0]
    assert entry.index("AegisWfpRegisterCallout(DriverObject)") < entry.index(
        "AegisWfpPrepareProofProvider()"
    ), "proof provider must be prepared after the callout/filter registers"

    unload = source.split("// ====== Unload ======", 1)[1].split(
        "// ====== IRP_MJ_CREATE", 1
    )[0]
    assert unload.index("AegisWfpCleanupProofFilters()") < unload.index(
        "AegisWfpUnregisterCallout()"
    ), "proof cleanup must run while the WFP engine is still open"

    assert "cleanupStatus = AegisWfpCleanupProofFilters();" in entry, (
        "prepare failure must attempt provider/proof cleanup before unregister"
    )
    assert "AegisWfpUnregisterCallout();" in entry


def test_driver_uses_static_session_for_persistent_proof_objects() -> None:
    """Persistent proof objects require a non-dynamic WFP engine session."""
    callout = DRIVER_CALLOUT.read_text(encoding="utf-8", errors="ignore")
    source = DRIVER_SOURCE.read_text(encoding="utf-8", errors="ignore")
    register = callout.split("NTSTATUS AegisWfpRegisterCallout", 1)[1].split(
        "VOID AegisWfpUnregisterCallout", 1
    )[0]

    assert "session.flags = 0;" in register
    assert "FWPM_SESSION_FLAG_DYNAMIC" not in register
    assert "FWPM_PROVIDER_FLAG_PERSISTENT" in source
    assert "FWPM_FILTER_FLAG_PERSISTENT" in source
    # The read-only attestation session is separate but also static: the
    # kernel WFP contract has no dynamic-session requirement, and a static
    # read-only session cannot leak persistent objects.
    query = source.split("NTSTATUS AegisWfpQueryFilter", 1)[1].split(
        "// ====== WFP Callout Registration", 1
    )[0]
    assert "session.flags = 0;" in query
    assert "FWPM_SESSION_FLAG_DYNAMIC" not in query


def test_driver_drains_irps_before_unload_teardown() -> None:
    """Unload must not close the engine or free the ring under an in-flight IRP."""
    source = DRIVER_SOURCE.read_text(encoding="utf-8", errors="ignore")
    unload = source.split("// ====== Unload ======", 1)[1].split(
        "// ====== IRP_MJ_CREATE", 1
    )[0]

    assert "IoInitializeRemoveLock(&g_RemoveLock, 'AEGR', 0, 0);" in source
    assert source.count("IoAcquireRemoveLock(&g_RemoveLock, Irp)") >= 3
    assert "IoReleaseRemoveLock(&g_RemoveLock, Irp);" in source
    assert "IoAcquireRemoveLock(&g_RemoveLock, NULL);" in unload
    assert "IoReleaseRemoveLockAndWait(&g_RemoveLock, NULL);" in unload
    assert unload.index("IoAcquireRemoveLock(&g_RemoveLock, NULL)") < unload.index(
        "IoReleaseRemoveLockAndWait"
    ), "the unload thread must hold the remove lock before releasing-and-waiting"
    assert unload.index("IoReleaseRemoveLockAndWait") < unload.index(
        "AegisWfpCleanupProofFilters()"
    ), "in-flight proof IOCTLs must drain before persistent cleanup"
    assert unload.index("IoReleaseRemoveLockAndWait") < unload.index(
        "AegisWfpUnregisterCallout()"
    ), "in-flight IOCTLs must drain before the engine handle closes"
    assert unload.index("IoReleaseRemoveLockAndWait") < unload.index(
        "ExFreePool(g_RingBuffer)"
    ), "in-flight event reads must drain before the ring is freed"


def test_classify_is_drained_before_callout_teardown() -> None:
    """Unload must not free the ring while a classify call can still write it."""
    source = DRIVER_SOURCE.read_text(encoding="utf-8", errors="ignore")
    callout = DRIVER_CALLOUT.read_text(encoding="utf-8", errors="ignore")
    classify = callout.split("void AegisWfpClassifyFn", 1)[1].split(
        "/* ====== Notify Callback", 1
    )[0]
    unregister = callout.split("VOID AegisWfpUnregisterCallout", 1)[1]

    assert "ExInitializeRundownProtection(&g_CalloutRundown);" in source
    assert "ExAcquireRundownProtection(&g_CalloutRundown)" in classify
    # Both directions share one emit helper; the ring lock lives there, so
    # the gate must be held before the call and released after it returns.
    emit = callout.split("static VOID AegisWfpEmitRecord", 1)[1].split(
        "/* ====== WFP Inbound Classify Callback", 1
    )[0]
    assert "KeAcquireSpinLock(&g_RingLock" in emit
    assert "KeReleaseSpinLock(&g_RingLock" in emit
    assert classify.index("ExAcquireRundownProtection") < classify.index(
        "AegisWfpEmitRecord(&hdr, layerData);"
    )
    assert "ExReleaseRundownProtection(&g_CalloutRundown);" in classify
    assert classify.index("ExReleaseRundownProtection") > classify.index(
        "AegisWfpEmitRecord(&hdr, layerData);"
    )
    assert "ExWaitForRundownProtectionRelease(&g_CalloutRundown);" in unregister
    assert unregister.index("ExWaitForRundownProtectionRelease") < unregister.index(
        "FwpmFilterDeleteById0"
    ), "no classify may still reference the ring when teardown starts"


def test_driver_rejects_and_removes_disabled_proof_filters() -> None:
    """A BFE-disabled persistent filter is absent, never confirmed enforcement."""
    source = DRIVER_SOURCE.read_text(encoding="utf-8", errors="ignore")
    match = source.split("static BOOLEAN AegisWfpFilterMatchesProof", 1)[1].split(
        "static BOOLEAN AegisWfpFilterMatchesRequest", 1
    )[0]
    recover = source.split("static NTSTATUS AegisWfpRecoverProofFilter", 1)[1].split(
        "/* Older builds installed one filter", 1
    )[0]

    assert "filter->flags & FWPM_FILTER_FLAG_DISABLED" in match
    assert "filter->numFilterConditions != 3" in match, (
        "attestation must reject a narrowed or widened proof filter"
    )
    assert "filter->flags & FWPM_FILTER_FLAG_DISABLED" in recover
    assert "FwpmFilterDeleteById0(g_WfpEngineHandle, filter->filterId)" in recover


def test_callout_removes_blm_callout_by_stable_key() -> None:
    """The runtime callout id must not be reused as the BLM callout id."""
    callout = DRIVER_CALLOUT.read_text(encoding="utf-8", errors="ignore")
    unregister = callout.split("VOID AegisWfpUnregisterCallout", 1)[1]
    assert "FwpmCalloutDeleteByKey0(g_WfpEngineHandle, &AEGIS_CALLOUT_KEY)" in callout
    assert "FwpmCalloutDeleteById0" not in callout
    assert "FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED" in callout
    assert unregister.index("FwpmFilterDeleteById0") < unregister.index(
        "FwpsCalloutUnregisterById0"
    ), "the terminating capture filter must go before runtime unregister"
    assert "KeDelayExecutionThread(KernelMode, FALSE, &delay);" in unregister, (
        "unload must not return while the runtime callout is still registered"
    )


def test_driver_cleanup_is_fail_closed_and_uncapped() -> None:
    """Cleanup must surface deletion/provider failures and drain all batches."""
    source = DRIVER_SOURCE.read_text(encoding="utf-8", errors="ignore")
    cleanup = source.split("NTSTATUS AegisWfpCleanupProofFilters", 1)[1].split(
        "// ====== DriverEntry", 1
    )[0]

    assert "for (;;)" in cleanup
    assert "snapshot.count == 0" in cleanup
    assert "AegisWfpRecordFirstFailure(&result, status)" in cleanup
    assert "resolved == 0" in cleanup
    assert "FwpmProviderDeleteByKey0" in cleanup
    assert "if (AegisWfpProviderNotFound(status))" in cleanup
    assert "AegisWfpDeleteLegacyProofFilter" in cleanup
    assert "AegisWfpFilterOwnedByProvider(filter)" in cleanup


def test_driver_empty_proof_enumeration_is_not_a_startup_failure() -> None:
    """A fresh provider has no filters; WFP not-found means empty, not fatal."""
    source = DRIVER_SOURCE.read_text(encoding="utf-8", errors="ignore")
    header = DRIVER_HEADER.read_text(encoding="utf-8", errors="ignore")
    helper = header.split("static __inline BOOLEAN AegisWfpFilterNotFound", 1)[
        1
    ].split("}", 1)[0]
    enum = source.split("static NTSTATUS AegisWfpEnumProofFilters", 1)[1].split(
        "static NTSTATUS AegisWfpRecoverProofFilter", 1
    )[0]

    for token in (
        "FWP_E_FILTER_NOT_FOUND",
        "STATUS_FWP_FILTER_NOT_FOUND",
        "STATUS_NOT_FOUND",
    ):
        assert token in helper, f"empty-enumeration helper misses {token}"

    create = enum.split("status = FwpmFilterCreateEnumHandle0", 1)[1].split(
        "for (;;)", 1
    )[0]
    listing = enum.split("status = FwpmFilterEnum0", 1)[1].split(
        "if (count == 0)", 1
    )[0]

    for block, terminator in ((create, "continue;"), (listing, "break;")):
        assert "AegisWfpFilterNotFound(status)" in block
        branch = block.split(
            "if (AegisWfpFilterNotFound(status))", 1
        )[1].split(terminator, 1)[0]
        assert "AegisWfpRecordFirstFailure" not in branch, (
            "empty enumeration must not be recorded as a startup failure"
        )


def test_driver_accepts_kernel_wfp_status_aliases() -> None:
    """Kernel WFP returns STATUS_FWP_*, not only the user-mode FWP_E_* form."""
    header = DRIVER_HEADER.read_text(encoding="utf-8", errors="ignore")
    source = DRIVER_SOURCE.read_text(encoding="utf-8", errors="ignore")
    callout = DRIVER_CALLOUT.read_text(encoding="utf-8", errors="ignore")

    for token in (
        "STATUS_FWP_CALLOUT_NOT_FOUND",
        "STATUS_FWP_FILTER_NOT_FOUND",
        "STATUS_FWP_PROVIDER_NOT_FOUND",
        "STATUS_FWP_ALREADY_EXISTS",
    ):
        assert token in header
    assert "if (AegisWfpAlreadyExists(status))" in source
    assert "AegisWfpProviderNotFound(status)" in source
    assert "AegisWfpCalloutNotFound(status)" in callout
    assert "status != FWP_E_FILTER_NOT_FOUND" not in source
    assert "status != FWP_E_CALLOUT_NOT_FOUND" not in callout


def test_driver_proof_provider_failure_is_staged_and_fail_closed() -> None:
    """A proof-provider failure must be diagnosable without hiding cleanup."""
    source = DRIVER_SOURCE.read_text(encoding="utf-8", errors="ignore")
    header = DRIVER_HEADER.read_text(encoding="utf-8", errors="ignore")
    callout = DRIVER_CALLOUT.read_text(encoding="utf-8", errors="ignore")
    entry = source.split("NTSTATUS DriverEntry", 1)[1].split(
        "// ====== Unload ======", 1
    )[0]

    assert "AEGIS_STAGE_PROOF_PROVIDER = 6" in header
    assert "NTSTATUS AegisWfpStartupFailure(" in header
    assert "AegisWfpStartupFailure(AEGIS_STAGE_PROOF_PROVIDER," in entry
    assert "cleanupStatus = AegisWfpCleanupProofFilters();" in entry
    assert "return startupStatus;" in entry
    assert "case AEGIS_STAGE_PROOF_PROVIDER:" in callout


def test_callout_has_no_fixed_key_proof_recovery() -> None:
    """Legacy key cleanup belongs to prepare/cleanup, not callout registration."""
    callout = DRIVER_CALLOUT.read_text(encoding="utf-8", errors="ignore")
    assert "recoveredProof" not in callout
    assert "FwpmFilterGetByKey0" not in callout
    assert "AEGIS_STAGE_PROOF_LOOKUP" not in callout


def test_wdk_build_and_host_scripts_are_pinned_and_secret_free() -> None:
    """The candidate hash cannot be a moving target between build and deploy."""
    build = (REPO_ROOT / "scripts" / "wdk_build_production.ps1").read_text(
        encoding="utf-8", errors="ignore"
    )
    sign = (REPO_ROOT / "scripts" / "sign_wfp_driver_20261024.ps1").read_text(
        encoding="utf-8", errors="ignore"
    )
    deploy = (REPO_ROOT / "scripts" / "deploy_wfp_driver_20261024.ps1").read_text(
        encoding="utf-8", errors="ignore"
    )
    runner = (REPO_ROOT / "scripts" / "run_g2_dupfilter_proof.ps1").read_text(
        encoding="utf-8", errors="ignore"
    )
    host = (REPO_ROOT / "tests" / "wfp" / "test_t11_windows_host.py").read_text(
        encoding="utf-8", errors="ignore"
    )
    cleanup = (REPO_ROOT / "scripts" / "cleanup_stale_aegis_firewall.ps1").read_text(
        encoding="utf-8", errors="ignore"
    )

    assert build.count("/Brepro") >= 2, "cl and link must both be deterministic"

    assert "[Parameter(Mandatory = $true)]" in sign
    assert "$ExpectedUnsignedSha256" in sign
    assert "/sha1" in sign
    assert "ConvertTo-SecureString" not in sign
    assert "$password" not in sign.lower()

    assert "$ExpectedCandidateSha256" in deploy
    assert "$ExpectedBackupSha256" in deploy
    assert "aegis_wfp.sys.before-" in deploy
    assert "Get-Sha256 $backup" in deploy
    assert "Copy-Item $backup $dst -Force" in deploy
    assert "aegisctl.py readiness" in deploy
    assert "daemon-rollback-stop-scm" in deploy

    assert "apply is disabled" in cleanup
    assert "Remove-NetFirewallRule" not in cleanup
    assert "DRY_RUN" in cleanup

    assert "$ExpectedDriverSha256" in runner
    assert "$ExpectedPepSha256" in runner
    assert "DUP_FILTER_SAME=true" in runner
    assert "DUP_UNBLOCK_RC=0" in runner
    assert "DUP_UNBLOCK_PRESENT=0" in runner
    assert "escalate reason=4" in runner
    assert "no_skip" in runner
    assert "AEGIS_EXPECTED_DRIVER_SHA256" in runner
    assert "AEGIS_EXPECTED_PEP_SHA256" in runner
    assert "AEGIS_EXPECTED_BRIDGE_SHA256" in runner
    assert "ARTIFACT_BRIDGE_LOADED_SHA256" in runner
    assert "BRIDGE_LOADED_PATH" in runner

    assert "AEGIS_EXPECTED_DRIVER_SHA256" in host
    assert "AEGIS_EXPECTED_PEP_SHA256" in host
    assert "AEGIS_EXPECTED_BRIDGE_SHA256" in host
    assert 'GetModuleHandleW("aegis_wfp_user.dll")' in host
