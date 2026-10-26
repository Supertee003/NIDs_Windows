"""EVT-231: WFP kernel payload-copy contract pins.

The WFP callout copies a bounded raw payload (up to
AEGIS_MAX_PAYLOAD_SIZE bytes as delivered at the transport layer) into
every ring record after the pinned 48-byte header, and the READ_EVENTS
path returns whole records only (never splits one). These pins fail if
the contract regresses to header-only records, partial reads, or silently
uncounted drops.

Static source pins only (E1): the kernel driver builds on this host; the
runtime behavior proof lives in the EVT-231 operator block evidence.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DRIVER_DIR = REPO_ROOT / "drivers" / "wfp_callout"
HEADER = DRIVER_DIR / "aegis_wfp.h"
DRIVER = DRIVER_DIR / "aegis_wfp.c"
CALLOUT = DRIVER_DIR / "aegis_wfp_callout.c"
TELEMETRY = REPO_ROOT / "src" / "capture" / "wfp_telemetry.zig"
PROOF_SCRIPT = REPO_ROOT / "scripts" / "run_wfp_l4_observe_only_proof.ps1"


def test_header_stays_48_bytes_with_bounded_payload_cap():
    text = HEADER.read_text(encoding="utf-8")
    assert "C_ASSERT(sizeof(AEGIS_EVENT_HEADER) == 48)" in text
    assert "#define AEGIS_MAX_PAYLOAD_SIZE     4096" in text


def test_callout_copies_bounded_payload_into_record():
    text = CALLOUT.read_text(encoding="utf-8")
    assert "NdisGetDataBuffer" in text
    assert "NET_BUFFER_LIST_FIRST_NB" in text
    assert "NET_BUFFER_DATA_LENGTH" in text
    assert "aegis_wfp_get_payload_slice" in text
    assert "payloadOffset" in text
    assert "AEGIS_MAX_CAPTURE_WINDOW" in text
    assert "g_PayloadScratch" in text
    emit = text.split("static VOID AegisWfpEmitRecord", 1)[1].split("/* ====== WFP Inbound", 1)[0]
    assert emit.index("KeAcquireSpinLock") < emit.index("NdisGetDataBuffer")
    assert "AEGIS_MAX_PAYLOAD_SIZE" in text
    # Fail-open must survive the payload path.
    assert "FWP_ACTION_PERMIT" in text
    # The old "payload deferred" placeholder must not return.
    assert "Payload length capture deferred" not in text


def test_read_path_returns_whole_records_and_counts_loss():
    text = DRIVER.read_text(encoding="utf-8")
    assert "whole event records" in text
    assert "AEGIS_MAX_PAYLOAD_SIZE" in text  # defensive header sanity guard
    assert "g_WfpTotalDrops" in text         # honest drop accounting
    assert "g_WfpTotalBytesRead" in text
    assert "g_PayloadScratch" in text        # scratch alloc/free wired


def test_stats_populate_all_counters():
    text = DRIVER.read_text(encoding="utf-8")
    for field in (
        "totalEventsWritten",
        "totalDrops",
        "totalBytesWritten",
        "totalBytesRead",
    ):
        assert f"stats->{field}" in text


def test_zig_loop_documents_bounded_copy():
    text = TELEMETRY.read_text(encoding="utf-8")
    assert "AEGIS_MAX_PAYLOAD_SIZE" in text
    assert "payload_length == 0 means empty, unavailable, or unsupported/malformed" in text
    # The stale "5-tuples only, payload_length = 0 by construction" claim
    # must not return: the driver now carries bounded raw bytes.
    assert "driver ring carries 5-tuples" not in text


def test_host_proof_script_parses_variable_records():
    text = PROOF_SCRIPT.read_text(encoding="utf-8")
    assert "EVT-231" in text
    # The fixed-48-byte-stride read hack must be retired: variable records
    # would stall the old 4080-byte drain on any record >= 4080 bytes.
    assert "4080" not in text
    assert "payloadLength" in text
