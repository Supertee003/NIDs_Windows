"""O2: kernel capture must cover both IPv4 transport directions.

The WFP driver registers a second callout at
FWPM_LAYER_OUTBOUND_TRANSPORT_V4 and marks those records with
header.direction=1. The 48-byte record and ring contract are unchanged;
the Zig reader must forward the direction into the canonical event so
detection/forensics can attribute outbound traffic correctly.

Static source pins only (E1/E2): the host execution proof is a separate
elevated step.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DRIVER_DIR = REPO_ROOT / "drivers" / "wfp_callout"
HEADER = DRIVER_DIR / "aegis_wfp.h"
DRIVER = DRIVER_DIR / "aegis_wfp.c"
CALLOUT = DRIVER_DIR / "aegis_wfp_callout.c"
TELEMETRY = REPO_ROOT / "src" / "capture" / "wfp_telemetry.zig"
QUEUE = REPO_ROOT / "src" / "pipeline" / "event_queue.zig"
PROCESSOR = REPO_ROOT / "src" / "pipeline" / "event_processor.zig"
FORENSIC = REPO_ROOT / "src" / "forensic" / "forensic_pipeline.zig"
HANDLER = REPO_ROOT / "src" / "control" / "handler_registry.zig"


def test_header_declares_outbound_callout_identity() -> None:
    header = HEADER.read_text(encoding="utf-8")
    assert "extern const GUID AEGIS_OUTBOUND_CALLOUT_KEY;" in header
    assert "extern UINT32         g_OutboundCalloutId;" in header
    assert "extern UINT64         g_OutboundCaptureFilterId;" in header
    # The shared record contract is unchanged by O2.
    assert "C_ASSERT(sizeof(AEGIS_EVENT_HEADER) == 48)" in header


def test_driver_registers_outbound_layer_and_teardown() -> None:
    source = DRIVER.read_text(encoding="utf-8")
    callout = CALLOUT.read_text(encoding="utf-8")

    assert "DEFINE_GUID(AEGIS_OUTBOUND_CALLOUT_KEY" in source
    assert "FWPM_LAYER_OUTBOUND_TRANSPORT_V4" in callout
    assert "AegisWfpOutboundClassifyFn" in callout

    register = callout.split("NTSTATUS AegisWfpRegisterCallout", 1)[1].split(
        "VOID AegisWfpUnregisterCallout", 1
    )[0]
    assert register.count("status = FwpmCalloutAdd0(") == 2
    assert register.count("status = FwpsCalloutRegister0(") == 2
    assert register.count("status = FwpmFilterAdd0(") == 2
    # A failure after the inbound pair is live must not leave it registered.
    assert "AegisWfpUnregisterCallout();" in register

    unregister = callout.split("VOID AegisWfpUnregisterCallout", 1)[1]
    assert "g_OutboundCaptureFilterId" in unregister
    assert "g_OutboundCalloutId" in unregister
    assert unregister.index("g_OutboundCaptureFilterId") < unregister.index(
        "FwpmEngineClose0"
    )
    assert "AEGIS_OUTBOUND_CALLOUT_KEY" in unregister


def test_outbound_classify_marks_direction_and_local_source() -> None:
    callout = CALLOUT.read_text(encoding="utf-8")
    outbound = callout.split("void AegisWfpOutboundClassifyFn", 1)[1].split(
        "/* ====== Notify Callback", 1
    )[0]

    assert "hdr.direction  = 1;" in outbound
    assert "FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS" in outbound
    assert "FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS" in outbound
    assert "FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT" in outbound
    assert "FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT" in outbound
    # Fail-open and rundown discipline match the proven inbound path.
    assert "FWP_ACTION_PERMIT" in outbound
    assert "ExAcquireRundownProtection" in outbound
    assert "ExReleaseRundownProtection" in outbound
    # Both directions share one emit path (no divergent ring writer).
    inbound = callout.split("void AegisWfpClassifyFn", 1)[1].split(
        "void AegisWfpOutboundClassifyFn", 1
    )[0]
    assert "AegisWfpEmitRecord(&hdr, layerData);" in inbound
    assert "AegisWfpEmitRecord(&hdr, layerData);" in outbound


def test_zig_reader_forwards_kernel_direction() -> None:
    text = TELEMETRY.read_text(encoding="utf-8")
    assert ".direction = hdr.direction," in text
    assert "ce.direction = rec.direction;" in text
    assert "direction: u8," in text


def test_direction_survives_queue_and_forensic_readback() -> None:
    queue = QUEUE.read_text(encoding="utf-8")
    processor = PROCESSOR.read_text(encoding="utf-8")
    forensic = FORENSIC.read_text(encoding="utf-8")
    handler = HANDLER.read_text(encoding="utf-8")

    assert "direction: ?u8 = null" in queue
    assert "if (ce.direction > 1) return false;" in queue
    assert "qe.direction = direction;" in queue
    assert "tcp_flags, ce.direction" in queue
    assert "forensic_ring.appendWithDirection" in processor
    assert "pub fn appendWithDirection" in forensic
    assert "DIRECTION_METADATA_VERSION" in forensic
    assert '\\"direction\\":{s}' in handler
    assert handler.count("directionJson(header)") == 3  # list, show, export
