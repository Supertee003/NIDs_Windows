"""Windows host verification for the Rust PEP -> WFP adapter path.

Run explicitly with AEGIS_RUN_WFP_HOST_TESTS=1 on a test-signed Windows host
with the AEGIS WFP driver installed. The test never calls the WFP helper
without first entering through aegis_pep.dll.

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
here instead of silently mis-driving the enforcement authority.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PEP_DLL = REPO_ROOT / "target" / "release" / "aegis_pep.dll"
HOST_TEST_ENABLED = os.environ.get("AEGIS_RUN_WFP_HOST_TESTS") == "1"

# Canonical PEP decision codes (rust-src/lib.rs).
DECISION_ALLOW = 0
DECISION_BLOCK = 1
DECISION_ESCALATE = 4

# `reason` semantics for DECISION_ESCALATE.
REASON_AUTHORIZATION_DENIED = 1
REASON_HOST_EFFECT_UNAVAILABLE = 4

# `policy.Action` ordinals (src/policy/policy_ir.zig). The PEP consumes the
# policy.Action ABI, not the PepDecision enum.
ACTION_PASS = 0
ACTION_BLOCK = 4

# Rust returns these from aegis_pep_unblock_ip.
PEP_UNBLOCK_NO_CAPABILITY = -3
PEP_UNBLOCK_RECEIPT_REQUIRED = -4


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


def assert_pep_abi_layout() -> None:
    """Pin the byte layout against the canonical CONTRACT-02 offsets."""
    assert ctypes.sizeof(PepContext) == 24, "PepContext must be 24 bytes"
    assert ctypes.sizeof(PepRequest) == 64, "PepRequest must be 64 bytes"
    assert ctypes.sizeof(PepResponse) == 24, "PepResponse must be 24 bytes"

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
    assert PepRequest.ctx.offset == 40

    assert PepResponse.decision.offset == 0
    assert PepResponse.reason.offset == 4
    assert PepResponse.quota_remaining.offset == 8
    assert PepResponse.signed_by.offset == 12
    assert PepResponse.filter_id.offset == 16


def test_pep_abi_layout_matches_contract_02() -> None:
    """Runs on every host: the declared ABI must match CONTRACT-02."""
    assert_pep_abi_layout()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows")
@pytest.mark.skipif(not HOST_TEST_ENABLED, reason="set AEGIS_RUN_WFP_HOST_TESTS=1")
def test_rust_pep_blocks_and_unblocks_on_windows() -> None:
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
            severity=4,
            ctx=PepContext(
                caller_pid=os.getpid(),
                caller_capability_mask=0x01,
                request_id=0x11010001,
                policy_version=0,
            ),
        )
        response = PepResponse()
        assert pep.aegis_pep_enforce(ctypes.byref(request), ctypes.byref(response)) == 0

        # Invariant that must hold on every host, WFP or not: the sole
        # enforcement authority never answers ALLOW to a privileged BLOCK
        # request. Returning ALLOW here would be a fail-open.
        assert response.decision != DECISION_ALLOW, (
            "PEP answered ALLOW to a privileged BLOCK request; this is a "
            f"fail-open on the enforcement authority (decision={response.decision})"
        )

        if response.decision != DECISION_BLOCK:
            # No WFP host effect provider on this host. CONTRACT-02 requires
            # the PEP to fail closed, so ESCALATE/reason=HOST_EFFECT_UNAVAILABLE
            # is the correct observable and E5 host verification is not claimed.
            assert response.decision == DECISION_ESCALATE, (
                f"expected BLOCK or fail-closed ESCALATE, got {response.decision}"
            )
            assert response.reason == REASON_HOST_EFFECT_UNAVAILABLE, (
                f"expected reason={REASON_HOST_EFFECT_UNAVAILABLE} "
                f"(host effect unavailable), got {response.reason}"
            )
            pytest.skip(
                "WFP host effect provider unavailable — fail-closed ESCALATE "
                "observed. Run on a test-signed host with the AEGIS WFP driver "
                "installed to claim E5 Windows enforcement verification."
            )

        # WFP-capable host: a concrete filter must have been installed.
        assert response.filter_id != 0, "BLOCK without an installed WFP filter_id"

        # Receipt-aware unblock is required; IP-only cleanup is intentionally
        # rejected by the canonical PEP so it cannot bypass receipt ownership.
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
