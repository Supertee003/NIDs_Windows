"""Windows host verification for the Rust PEP -> WFP adapter path.

Run explicitly with AEGIS_RUN_WFP_HOST_TESTS=1 on a test-signed Windows host
with the AEGIS WFP driver installed. The test never calls the WFP helper
without first entering through aegis_pep.dll.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PEP_DLL = REPO_ROOT / "target" / "release" / "aegis_pep.dll"
HOST_TEST_ENABLED = os.environ.get("AEGIS_RUN_WFP_HOST_TESTS") == "1"


class PepContext(ctypes.Structure):
    _fields_ = [
        ("caller_pid", ctypes.c_uint32),
        ("caller_capability_mask", ctypes.c_uint32),
        ("request_id", ctypes.c_uint64),
        ("reserved", ctypes.c_uint32),
    ]


class PepRequest(ctypes.Structure):
    _fields_ = [
        ("decision_kind", ctypes.c_uint8),
        ("flow_id", ctypes.c_uint64),
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
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
    ]


@pytest.mark.skipif(os.name != "nt", reason="requires Windows")
@pytest.mark.skipif(not HOST_TEST_ENABLED, reason="set AEGIS_RUN_WFP_HOST_TESTS=1")
def test_rust_pep_blocks_and_unblocks_on_windows() -> None:
    assert PEP_DLL.is_file(), f"missing PEP artifact: {PEP_DLL}"

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
            flow_id=0xAE110001,
            src_ip=0xCB00710A,  # 203.0.113.10, TEST-NET-3
            dst_ip=0x08080808,
            src_port=40000,
            dst_port=443,
            policy_id=0x1101,
            severity=4,
            ctx=PepContext(
                caller_pid=os.getpid(),
                caller_capability_mask=0x01,
                request_id=0x11010001,
                reserved=0,
            ),
        )
        response = PepResponse()
        assert pep.aegis_pep_enforce(ctypes.byref(request), ctypes.byref(response)) == 0
        assert response.decision == 1, (
            "PEP did not return BLOCK; verify the WFP driver is installed "
            f"(decision={response.decision}, reason={response.reason})"
        )
        assert pep.aegis_pep_unblock_ip(
            request.src_ip,
            request.ctx.caller_pid,
            request.ctx.caller_capability_mask,
            request.ctx.request_id + 1,
        ) == 0
    finally:
        pep.aegis_pep_shutdown()
