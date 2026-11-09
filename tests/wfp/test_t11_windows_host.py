"""Windows host verification for the Rust PEP detection-only contract.

Run explicitly with AEGIS_RUN_WFP_HOST_TESTS=1 on a test-signed Windows host
with the AEGIS WFP driver installed. The tests enter through aegis_pep.dll and
pin the confirmed product decision (issue #25): policy evaluation is evidence
only, block/quarantine requests are reported as ESCALATE reason 8, and no
WFP filter or other host effect may be produced.

CONTRACT-02 (PEP ABI) is the single source of truth for these layouts. The
declarations below must reproduce byte-for-byte the Rust `#[repr(C)]` structs
in `rust-src/lib.rs` and the Zig `extern struct`s in
`src/policy/pep_bindings.zig`:

    PepContext  = 24 bytes
    PepRequest  = 64 bytes
    PepResponse = 24 bytes

A prior revision of this file omitted `requested_action` and `protocol` from
`PepRequest` and `filter_id` from `PepResponse`. Because the omitted fields are
one byte each, every later field shifted by one byte, so the PEP read
`requested_action == 0 == ACTION_PASS` and always answered ALLOW, and the
response write of `filter_id` landed 8 bytes past the Python allocation.
`assert_pep_abi_layout()` below exists so that drift like that fails loudly
here instead of silently mis-driving the policy evaluation boundary.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
from ctypes import wintypes
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PEP_DLL = REPO_ROOT / "target" / "release" / "aegis_pep.dll"
DEFAULT_DRIVER_SYS = (
    Path(os.environ.get("SystemRoot", r"C:\Windows"))
    / "System32"
    / "drivers"
    / "aegis_wfp.sys"
)
# The proof runner resolves the service ImagePath and pins that exact file. A
# host with a non-default driver path must not silently hash a different file.
DRIVER_SYS = Path(os.environ.get("AEGIS_DRIVER_PATH", str(DEFAULT_DRIVER_SYS)))
HOST_TEST_ENABLED = os.environ.get("AEGIS_RUN_WFP_HOST_TESTS") == "1"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def _assert_artifact_hash(path: Path, env_name: str, label: str) -> str:
    """Print and optionally pin the exact bytes used by this host proof."""
    actual = _sha256_file(path)
    print(f"ARTIFACT_{label}_SHA256={actual}")
    expected = os.environ.get(env_name, "").strip().upper()
    if expected:
        assert actual == expected, f"{label} hash mismatch: {actual} != {expected}"
    return actual


def _loaded_bridge_path() -> str | None:
    """Return the bridge module the PEP actually loaded, not a candidate path."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    kernel32.GetModuleFileNameW.argtypes = [
        wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD,
    ]
    kernel32.GetModuleFileNameW.restype = wintypes.DWORD
    module = kernel32.GetModuleHandleW("aegis_wfp_user.dll")
    if not module:
        return None
    buf = ctypes.create_unicode_buffer(32768)
    copied = kernel32.GetModuleFileNameW(module, buf, len(buf))
    return buf.value if copied else None


def _assert_loaded_bridge_hash() -> str:
    path = _loaded_bridge_path()
    assert path, "aegis_wfp_user.dll is not loaded in this process"
    print(f"BRIDGE_LOADED_PATH={path}")
    return _assert_artifact_hash(
        Path(path), "AEGIS_EXPECTED_BRIDGE_SHA256", "BRIDGE_LOADED"
    )

# Canonical PEP decision codes (rust-src/lib.rs).
DECISION_ALLOW = 0
DECISION_BLOCK = 1
DECISION_QUARANTINE = 3
DECISION_ESCALATE = 4

# `reason` semantics for DECISION_ESCALATE.
REASON_AUTHORIZATION_DENIED = 1
# DETECTION-ONLY (issue #25): a policy that requests block/quarantine is
# reported as an escalation for human review; there is no host effect.
REASON_DETECTION_ONLY = 8

# `policy.Action` ordinals (src/policy/policy_ir.zig). The PEP consumes the
# policy.Action ABI, not the PepDecision enum.
ACTION_PASS = 0
ACTION_BLOCK = 4
ACTION_QUARANTINE = 5

# Rust returns these from aegis_pep_unblock_ip.
PEP_UNBLOCK_NO_CAPABILITY = -3
PEP_UNBLOCK_RECEIPT_REQUIRED = -4

# The current driver derives one key per (direction, tuple) and owns it via a
# provider, so a repeated BLOCK returns the existing filter id. This retired
# static key belongs only to older builds; pre-clean it best-effort (FWPM
# direct) so a re-run cannot trip over old litter on an already-loaded driver.
PROOF_FILTER_KEY = "{b2c3d4e5-f607-4b8c-9d0e-1f2a3b4c5d6e}"
FWP_E_FILTER_NOT_FOUND = 0x80320003
STATUS_FWP_FILTER_NOT_FOUND = 0xC0220003
NTSTATUS_NOT_FOUND = 0xC0000034
STATUS_NOT_FOUND = 0x80000002


def _guid_struct(key: str):
    class GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_uint32),
                    ("Data2", ctypes.c_uint16),
                    ("Data3", ctypes.c_uint16),
                    ("Data4", ctypes.c_uint8 * 8)]
    s = key.strip().strip("{}")
    parts = s.split("-")
    d4 = bytes.fromhex(parts[3] + parts[4])
    return GUID(int(parts[0], 16), int(parts[1], 16), int(parts[2], 16),
                (ctypes.c_uint8 * 8)(*d4))


def _delete_stale_proof_filter() -> int:
    """Delete the retired single-key proof filter (best effort).

    The current driver no longer mints this key; its provider-owned per-tuple
    filters are cleaned by the driver/test receipt. Returns the FWPM rc
    (0 deleted, FWP_E_FILTER_NOT_FOUND when clean). Never raises: a dirty host
    must not fail collection, and a stuck filter surfaces at BLOCK time
    instead.

    Expected noise on the clean-host path: FwpmFilterDeleteByKey0 can
    raise-and-catch an internal first-chance exception; faulthandler's
    vectored handler logs it as "Windows fatal exception: code
    0x80320003" while the FWPM/RPC stack then handles it normally. Benign
    and count-neutral -- the call still returns the rc."""
    try:
        fwpuclnt = ctypes.WinDLL("fwpuclnt.dll")
        fwpuclnt.FwpmEngineOpen0.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32,
                                             ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.POINTER(ctypes.c_void_p)]
        fwpuclnt.FwpmEngineOpen0.restype = ctypes.c_uint32
        fwpuclnt.FwpmFilterDeleteByKey0.argtypes = [ctypes.c_void_p,
                                                    ctypes.c_void_p]
        fwpuclnt.FwpmFilterDeleteByKey0.restype = ctypes.c_uint32
        fwpuclnt.FwpmEngineClose0.argtypes = [ctypes.c_void_p]
        engine = ctypes.c_void_p()
        if fwpuclnt.FwpmEngineOpen0(None, 10, None, None,
                                    ctypes.byref(engine)) != 0:
            return -1
        try:
            return fwpuclnt.FwpmFilterDeleteByKey0(
                engine, ctypes.byref(_guid_struct(PROOF_FILTER_KEY)))
        finally:
            fwpuclnt.FwpmEngineClose0(engine)
    except Exception:
        return -1


class PepContext(ctypes.Structure):
    _fields_ = [
        ("caller_pid", ctypes.c_uint32),
        ("caller_capability_mask", ctypes.c_uint32),
        ("request_id", ctypes.c_uint64),
        ("policy_version", ctypes.c_uint32),
    ]


class PepRequest(ctypes.Structure):
    _fields_ = [
        ("decision_kind", ctypes.c_uint8),
        ("requested_action", ctypes.c_uint8),
        ("flow_id", ctypes.c_uint64),
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("policy_id", ctypes.c_uint32),
        ("severity", ctypes.c_uint8),
        # FFI-001 direction byte: 0=outbound dst_ip/dst_port,
        # 1=inbound peer src_ip + local dst_port. Reuses historical padding;
        # the struct stays 64 bytes and ctx stays at offset 40.
        ("direction", ctypes.c_uint8),
        ("ctx", PepContext),
    ]


class PepResponse(ctypes.Structure):
    _fields_ = [
        ("decision", ctypes.c_uint8),
        ("reason", ctypes.c_uint32),
        ("quota_remaining", ctypes.c_uint32),
        ("signed_by", ctypes.c_uint32),
        ("filter_id", ctypes.c_uint64),
    ]


class PepAssessmentResponse(ctypes.Structure):
    """Rust `#[repr(C)]` evidence-only response (16 bytes)."""
    _fields_ = [
        ("decision", ctypes.c_uint8),
        ("reason", ctypes.c_uint32),
        ("host_effect_confirmed", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 7),
    ]


class PepFilterState(ctypes.Structure):
    """Rust `#[repr(C, packed)] PepFilterState` (20 bytes)."""
    _pack_ = 1
    _fields_ = [
        ("filter_id", ctypes.c_uint64),
        ("remote_ipv4", ctypes.c_uint32),
        ("remote_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("present", ctypes.c_uint8),
        ("provider_status", ctypes.c_uint32),
    ]


def assert_pep_abi_layout() -> None:
    """Pin the byte layout against the canonical CONTRACT-02 offsets."""
    assert ctypes.sizeof(PepContext) == 24, "PepContext must be 24 bytes"
    assert ctypes.sizeof(PepRequest) == 64, "PepRequest must be 64 bytes"
    assert ctypes.sizeof(PepResponse) == 24, "PepResponse must be 24 bytes"
    assert ctypes.sizeof(PepAssessmentResponse) == 16, "PepAssessmentResponse must be 16 bytes"

    assert PepContext.caller_pid.offset == 0
    assert PepContext.caller_capability_mask.offset == 4
    assert PepContext.request_id.offset == 8
    assert PepContext.policy_version.offset == 16

    assert PepRequest.decision_kind.offset == 0
    assert PepRequest.requested_action.offset == 1
    assert PepRequest.flow_id.offset == 8
    assert PepRequest.src_ip.offset == 16
    assert PepRequest.dst_ip.offset == 20
    assert PepRequest.src_port.offset == 24
    assert PepRequest.dst_port.offset == 26
    assert PepRequest.protocol.offset == 28
    assert PepRequest.policy_id.offset == 32
    assert PepRequest.severity.offset == 36
    assert PepRequest.direction.offset == 37
    assert PepRequest.ctx.offset == 40

    assert PepResponse.decision.offset == 0
    assert PepResponse.reason.offset == 4
    assert PepResponse.quota_remaining.offset == 8
    assert PepResponse.signed_by.offset == 12
    assert PepResponse.filter_id.offset == 16

    assert PepAssessmentResponse.decision.offset == 0
    assert PepAssessmentResponse.reason.offset == 4
    assert PepAssessmentResponse.host_effect_confirmed.offset == 8
    assert PepAssessmentResponse.reserved.offset == 9

    # Rust `#[repr(C, packed)] PepFilterState` (read-back state).
    assert ctypes.sizeof(PepFilterState) == 20
    assert PepFilterState.filter_id.offset == 0
    assert PepFilterState.remote_ipv4.offset == 8
    assert PepFilterState.remote_port.offset == 12
    assert PepFilterState.protocol.offset == 14
    assert PepFilterState.present.offset == 15
    assert PepFilterState.provider_status.offset == 16


def test_pep_abi_layout_matches_contract_02() -> None:
    """Runs on every host: the declared ABI must match CONTRACT-02."""
    assert_pep_abi_layout()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows")
@pytest.mark.skipif(not HOST_TEST_ENABLED, reason="set AEGIS_RUN_WFP_HOST_TESTS=1")
def test_rust_pep_reports_detection_only_for_block_on_windows() -> None:
    """DETECTION-ONLY (issue #25): a BLOCK request is evidence, not a filter."""
    assert PEP_DLL.is_file(), f"missing PEP artifact: {PEP_DLL}"
    assert_pep_abi_layout()

    pep = ctypes.WinDLL(str(PEP_DLL))
    pep.aegis_pep_init.restype = ctypes.c_int
    pep.aegis_pep_enforce.argtypes = [
        ctypes.POINTER(PepRequest), ctypes.POINTER(PepResponse)
    ]
    pep.aegis_pep_enforce.restype = ctypes.c_int
    pep.aegis_pep_unblock_ip.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint64,
    ]
    pep.aegis_pep_unblock_ip.restype = ctypes.c_int
    pep.aegis_pep_shutdown.restype = None

    assert pep.aegis_pep_init() == 0
    try:
        request = PepRequest(
            decision_kind=61,
            requested_action=ACTION_BLOCK,
            flow_id=0xAE110001,
            src_ip=0xCB00710A,  # 203.0.113.10, TEST-NET-3
            dst_ip=0x08080808,
            src_port=40000,
            dst_port=443,
            protocol=6,  # TCP
            policy_id=0x1101,
            severity=9,  # privileged severity still must not mint a filter
            ctx=PepContext(
                caller_pid=os.getpid(),
                caller_capability_mask=0x01,
                request_id=0x11010001,
                policy_version=0,
            ),
        )
        response = PepResponse()
        assert pep.aegis_pep_enforce(ctypes.byref(request), ctypes.byref(response)) == 0

        # The retired enforcement path must never come back on any host.
        assert response.decision == DECISION_ESCALATE, (
            "BLOCK must be reported as ESCALATE for human review, got "
            f"decision={response.decision}"
        )
        assert response.reason == REASON_DETECTION_ONLY, (
            f"expected reason={REASON_DETECTION_ONLY} (detection-only), "
            f"got {response.reason}"
        )
        assert response.filter_id == 0, (
            f"BLOCK minted a WFP filter (filter_id={response.filter_id}); "
            "the product is detection-only"
        )
        print("DETECTION_ONLY_BLOCK=true")
        print("DETECTION_ONLY_FILTER_ID=0")

        # IP-only cleanup stays receipt-required: a caller cannot use the
        # legacy cleanup surface to delete a filter it did not receive.
        assert pep.aegis_pep_unblock_ip(
            request.src_ip,
            request.ctx.caller_pid,
            request.ctx.caller_capability_mask,
            request.ctx.request_id + 1,
        ) == PEP_UNBLOCK_RECEIPT_REQUIRED
    finally:
        pep.aegis_pep_shutdown()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows")
@pytest.mark.skipif(not HOST_TEST_ENABLED, reason="set AEGIS_RUN_WFP_HOST_TESTS=1")
def test_rust_pep_reports_detection_only_for_quarantine_on_windows() -> None:
    """DETECTION-ONLY (issue #25): quarantine is the same escalation, no filter.

    This replaces the retired G2 duplicate-filter proof: there is no filter to
    duplicate, so the only honest host proof is that two identical inbound
    quarantine requests both escalate with no filter and no host effect.
    """
    assert PEP_DLL.is_file(), f"missing PEP artifact: {PEP_DLL}"
    if not DRIVER_SYS.is_file():
        pytest.skip(f"installed WFP driver not found: {DRIVER_SYS}")
    assert_pep_abi_layout()
    _assert_artifact_hash(PEP_DLL, "AEGIS_EXPECTED_PEP_SHA256", "PEP")
    _assert_artifact_hash(DRIVER_SYS, "AEGIS_EXPECTED_DRIVER_SHA256", "DRIVER")

    pep = ctypes.WinDLL(str(PEP_DLL))
    pep.aegis_pep_init.restype = ctypes.c_int
    pep.aegis_pep_enforce.argtypes = [
        ctypes.POINTER(PepRequest), ctypes.POINTER(PepResponse)
    ]
    pep.aegis_pep_enforce.restype = ctypes.c_int
    pep.aegis_pep_shutdown.restype = None

    assert pep.aegis_pep_init() == 0
    try:
        # TEST-NET-3 peer, local service port 8443: a scoped, harmless tuple.
        request = PepRequest(
            decision_kind=61,
            requested_action=ACTION_QUARANTINE,
            flow_id=0xD0F10002,
            src_ip=0xCB00710A,  # 203.0.113.10
            dst_ip=0,
            src_port=0,
            dst_port=8443,
            protocol=6,  # TCP
            policy_id=0xD0F10003,
            severity=9,
            direction=1,  # inbound WFP capture
            ctx=PepContext(
                caller_pid=os.getpid(),
                caller_capability_mask=0x01,
                request_id=0xD0F10001,
                policy_version=0,
            ),
        )

        for attempt in (1, 2):
            response = PepResponse()
            assert pep.aegis_pep_enforce(
                ctypes.byref(request), ctypes.byref(response)
            ) == 0, "PEP enforce must return a decision, not an error"
            assert response.decision == DECISION_ESCALATE, (
                f"attempt {attempt}: quarantine must escalate, got "
                f"decision={response.decision}, reason={response.reason}"
            )
            assert response.reason == REASON_DETECTION_ONLY, (
                f"attempt {attempt}: expected reason={REASON_DETECTION_ONLY}, "
                f"got {response.reason}"
            )
            assert response.filter_id == 0, (
                f"attempt {attempt}: quarantine minted filter "
                f"{response.filter_id}; the product is detection-only"
            )
            request.ctx.request_id += 1

        print("DETECTION_ONLY_QUARANTINE=true")
        print("DETECTION_ONLY_NO_FILTER=true")
    finally:
        pep.aegis_pep_shutdown()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows")
@pytest.mark.skipif(not HOST_TEST_ENABLED, reason="set AEGIS_RUN_WFP_HOST_TESTS=1")
def test_rust_pep_unblock_requires_capability_on_windows() -> None:
    assert PEP_DLL.is_file(), f"missing PEP artifact: {PEP_DLL}"
    assert_pep_abi_layout()

    pep = ctypes.WinDLL(str(PEP_DLL))
    pep.aegis_pep_init.restype = ctypes.c_int
    pep.aegis_pep_unblock_ip.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint64,
    ]
    pep.aegis_pep_unblock_ip.restype = ctypes.c_int
    pep.aegis_pep_shutdown.restype = None

    assert pep.aegis_pep_init() == 0
    try:
        # Without the privileged capability mask, cleanup is denied outright.
        assert pep.aegis_pep_unblock_ip(0xCB00710A, os.getpid(), 0, 1) == PEP_UNBLOCK_NO_CAPABILITY
    finally:
        pep.aegis_pep_shutdown()
