"""O2: kernel capture must cover both IPv4 transport directions.

The WFP driver registers a second callout at
FWPM_LAYER_OUTBOUND_TRANSPORT_V4 and marks those records with
header.direction=1. The 48-byte record and ring contract are unchanged;
the Zig reader must forward the direction into the canonical event so
detection/forensics can attribute outbound traffic correctly.

O1 (plan §26 ทาง A) adds the IPv4→IPv6 extension: two more capture pairs
at the IPv6 transport layers whose records lead the payload with a
32-byte identity sidecar (src16 ++ dst16) behind header flags bit0.

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
    # O1: four capture pairs now — v4 in/out + v6 in/out.
    assert register.count("status = FwpmCalloutAdd0(") == 4
    assert register.count("status = FwpsCalloutRegister0(") == 4
    assert register.count("status = FwpmFilterAdd0(") == 4
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
        "/* ====== O1 (plan", 1
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
    # Both directions share one emit path (no divergent ring writer); the
    # v4 path passes no sidecar (NULL/NULL).
    inbound = callout.split("void AegisWfpClassifyFn", 1)[1].split(
        "void AegisWfpOutboundClassifyFn", 1
    )[0]
    assert "AegisWfpEmitRecord(&hdr, layerData, NULL, NULL);" in inbound
    assert "AegisWfpEmitRecord(&hdr, layerData, NULL, NULL);" in outbound


def test_header_declares_v6_sidecar_contract() -> None:
    """O1 (§26 ทาง A): flags bit0 + 32-byte sidecar, 48-byte header intact."""
    header = HEADER.read_text(encoding="utf-8")
    assert "#define AEGIS_EVENT_FLAG_V6_SIDECAR 0x01" in header
    assert "#define AEGIS_V6_SIDECAR_SIZE       32" in header
    for ident in (
        "extern UINT32         g_InboundV6CalloutId;",
        "extern UINT64         g_InboundV6FilterId;",
        "extern UINT32         g_OutboundV6CalloutId;",
        "extern UINT64         g_OutboundV6FilterId;",
    ):
        assert ident in header
    # The 48-byte record stride is untouched: the sidecar lives inside the
    # payload tail the header's payload_length claim already covers.
    assert "C_ASSERT(sizeof(AEGIS_EVENT_HEADER) == 48)" in header


def test_driver_registers_v6_layers_and_teardown() -> None:
    """O1 (§26 ทาง A): IPv6 transport pairs share the ring and record."""
    source = DRIVER.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")
    callout = CALLOUT.read_text(encoding="utf-8")

    # Fresh callout identities; a v4 key is never reused for v6.
    assert "DEFINE_GUID(AEGIS_INBOUND_V6_CALLOUT_KEY" in source
    assert "DEFINE_GUID(AEGIS_OUTBOUND_V6_CALLOUT_KEY" in source
    assert "extern const GUID AEGIS_INBOUND_V6_CALLOUT_KEY;" in header
    assert "extern const GUID AEGIS_OUTBOUND_V6_CALLOUT_KEY;" in header
    assert "FWPM_LAYER_INBOUND_TRANSPORT_V6" in callout
    assert "FWPM_LAYER_OUTBOUND_TRANSPORT_V6" in callout

    register = callout.split("NTSTATUS AegisWfpRegisterCallout", 1)[1].split(
        "VOID AegisWfpUnregisterCallout", 1
    )[0]
    unregister = callout.split("VOID AegisWfpUnregisterCallout", 1)[1]
    for fn in ("AegisWfpInboundV6ClassifyFn", "AegisWfpOutboundV6ClassifyFn"):
        assert fn in register
    for ident in (
        "g_InboundV6CalloutId",
        "g_InboundV6FilterId",
        "g_OutboundV6CalloutId",
        "g_OutboundV6FilterId",
    ):
        assert ident in register
        assert ident in unregister
    # The v6 filters carry the same fail-open guard as the v4 filters.
    assert register.count("FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED") == 4

    # v6 pairs are removed before the v4 pairs; the BLM keys are deleted.
    assert unregister.index("g_OutboundV6FilterId") < unregister.index(
        "g_OutboundCaptureFilterId"
    )
    assert "AEGIS_INBOUND_V6_CALLOUT_KEY" in unregister
    assert "AEGIS_OUTBOUND_V6_CALLOUT_KEY" in unregister


def test_v6_classify_marks_direction_and_emits_sidecar() -> None:
    """O1 (§26 ทาง A): v6 records ride the same ring with a 32-byte sidecar."""
    callout = CALLOUT.read_text(encoding="utf-8")
    inbound = callout.split("void AegisWfpInboundV6ClassifyFn", 1)[1].split(
        "/* ====== WFP Outbound V6 Classify Callback", 1
    )[0]
    outbound = callout.split("void AegisWfpOutboundV6ClassifyFn", 1)[1].split(
        "/* ====== Notify Callback", 1
    )[0]

    assert "hdr.direction  = 0;" in inbound
    assert "hdr.direction  = 1;" in outbound
    # Driver-side layer discriminators (the canonical layer stays WFP=1 in
    # the Zig decoder; this byte is diagnostic only).
    assert "hdr.layer_id = 2;" in inbound
    assert "hdr.layer_id = 3;" in outbound

    assert "FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_PROTOCOL" in inbound
    assert "FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS" in inbound
    assert "FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS" in inbound
    assert "FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_PORT" in inbound
    assert "FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_PORT" in inbound
    assert "FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_PROTOCOL" in outbound
    assert "FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS" in outbound
    assert "FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS" in outbound
    assert "FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_PORT" in outbound
    assert "FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_PORT" in outbound

    for fn in (inbound, outbound):
        # Full v6 identity rides the sidecar as raw byte arrays; the u32
        # fields are the first 4 bytes composed as a BE integer value.
        assert "value.byteArray16" in fn
        assert "AegisWfpV6Prefix32" in fn
        assert "AegisWfpEmitRecord(&hdr, layerData, NULL, NULL);" in fn
    assert "remote6->byteArray16, local6->byteArray16);" in inbound
    assert "local6->byteArray16, remote6->byteArray16);" in outbound
    # u32 identity convention: first 4 sidecar bytes, big-endian value.
    assert "((UINT32)addr[0] << 24)" in callout


def test_emit_writes_v6_sidecar_within_payload_budget() -> None:
    """O1 (§26 ทาง A): flag bit0 is set only alongside a written sidecar,
    and the body budget shrinks so payload_length never exceeds the
    reader's AEGIS_MAX_PAYLOAD_SIZE reset contract."""
    callout = CALLOUT.read_text(encoding="utf-8")
    emit = callout.split("static VOID AegisWfpEmitRecord", 1)[1].split(
        "/* ====== WFP Inbound Classify Callback", 1
    )[0]

    assert "UINT8  sidecarBuf[AEGIS_V6_SIDECAR_SIZE];" in emit
    assert "src6 != NULL && dst6 != NULL" in emit
    assert "hdr->flags |= AEGIS_EVENT_FLAG_V6_SIDECAR;" in emit
    # The sidecar shares the payload budget (the reader resets the ring on
    # any larger claim).
    assert "AEGIS_MAX_PAYLOAD_SIZE - sidecarLen" in emit
    assert "hdr->payload_length = (UINT32)(sidecarLen + copyLen);" in emit
    # Record order: header, then the identity sidecar, then the L7 body.
    assert emit.index(
        "AegisWfpRingWrite(hdr, sizeof(AEGIS_EVENT_HEADER))"
    ) < emit.index("AegisWfpRingWrite(sidecarBuf, sidecarLen)")
    assert emit.index(
        "AegisWfpRingWrite(sidecarBuf, sidecarLen)"
    ) < emit.index("AegisWfpRingWrite(payload, copyLen)")
    # A gather failure degrades to header + sidecar, never a flagged
    # record without its 32 bytes.
    assert "hdr->payload_length = (UINT32)sidecarLen;" in emit


def test_zig_reader_forwards_kernel_direction() -> None:
    text = TELEMETRY.read_text(encoding="utf-8")
    assert ".direction = hdr.direction," in text
    assert "ce.direction = rec.direction;" in text
    assert "direction: u8," in text


def test_zig_reader_decodes_v6_sidecar() -> None:
    """O1 (§26 ทาง A): the Zig ring decoder owns the sidecar contract."""
    text = TELEMETRY.read_text(encoding="utf-8")
    assert "pub const FLAG_V6_SIDECAR: u8 = 1 << 0;" in text
    assert "pub const V6_SIDECAR_SIZE: usize = 32;" in text
    assert "src_ipv6: ?[16]u8 = null," in text
    # The ring advance follows the header claim (sidecar included), not
    # the stripped payload view.
    assert "rec.advanceBytes()" in text


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
