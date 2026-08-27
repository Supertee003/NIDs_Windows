"""tests/contracts/test_wire_contract.py - STEP 2 Cross-Language Contract Test

Verifies that the Python reference wire codec produces byte-identical output
to the expected test vectors. Other languages (Zig, C++, Rust, Go) must
produce the same bytes for the same input.

Run: python tests/contracts/test_wire_contract.py
"""

from __future__ import annotations

import os
import sys
import struct
import zlib
import unittest

# Make shared/wire/ importable from project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "shared", "wire"))

from wire_codec import (
    WireCodec, WireHeader, CanonicalEvent,
    EventSource, EventType, PolicyAction, PayloadType,
    WIRE_MAGIC, WIRE_VERSION, WIRE_HEADER_SIZE, WIRE_PAYLOAD_SIZE, WIRE_FRAME_SIZE,
    EVENT_MAGIC, EVENT_VERSION,
)


class TestWireHeaderEncoding(unittest.TestCase):
    """Verify wire header byte layout matches wire_v1.md spec."""

    def test_header_size_is_16_bytes(self):
        h = WireHeader(magic=WIRE_MAGIC, version=WIRE_VERSION, payload_type=0,
                       payload_length=109, crc32=0xDEADBEEF)
        encoded = WireCodec.encode_header(h)
        self.assertEqual(len(encoded), WIRE_HEADER_SIZE)
        self.assertEqual(len(encoded), 16)

    def test_header_magic_at_offset_0_little_endian(self):
        h = WireHeader(magic=WIRE_MAGIC, version=WIRE_VERSION, payload_type=0,
                       payload_length=109, crc32=0xDEADBEEF)
        encoded = WireCodec.encode_header(h)
        # 0x57455631 little-endian = 31 56 45 57
        self.assertEqual(encoded[0], 0x31, f"magic[0] should be 0x31, got 0x{encoded[0]:02X}")
        self.assertEqual(encoded[1], 0x56)
        self.assertEqual(encoded[2], 0x45)
        self.assertEqual(encoded[3], 0x57)

    def test_header_version_at_offset_4(self):
        h = WireHeader(magic=WIRE_MAGIC, version=WIRE_VERSION, payload_type=0,
                       payload_length=109, crc32=0)
        encoded = WireCodec.encode_header(h)
        self.assertEqual(encoded[4], 1, "version LSB at offset 4")
        self.assertEqual(encoded[5], 0, "version MSB at offset 5")

    def test_header_payload_type_at_offset_6(self):
        h = WireHeader(magic=WIRE_MAGIC, version=WIRE_VERSION,
                       payload_type=int(PayloadType.command),
                       payload_length=8, crc32=0)
        encoded = WireCodec.encode_header(h)
        self.assertEqual(encoded[6], 1, "payload_type LSB at offset 6")
        self.assertEqual(encoded[7], 0)

    def test_header_payload_length_at_offset_8(self):
        h = WireHeader(magic=WIRE_MAGIC, version=WIRE_VERSION, payload_type=0,
                       payload_length=109, crc32=0)
        encoded = WireCodec.encode_header(h)
        self.assertEqual(encoded[8], 109, "payload_length LSB at offset 8")
        self.assertEqual(encoded[9], 0)
        self.assertEqual(encoded[10], 0)
        self.assertEqual(encoded[11], 0)

    def test_header_crc32_at_offset_12(self):
        h = WireHeader(magic=WIRE_MAGIC, version=WIRE_VERSION, payload_type=0,
                       payload_length=0, crc32=0xDEADBEEF)
        encoded = WireCodec.encode_header(h)
        self.assertEqual(encoded[12], 0xEF)
        self.assertEqual(encoded[13], 0xBE)
        self.assertEqual(encoded[14], 0xAD)
        self.assertEqual(encoded[15], 0xDE)

    def test_header_round_trip_preserves_all_fields(self):
        original = WireHeader(magic=WIRE_MAGIC, version=WIRE_VERSION,
                              payload_type=int(PayloadType.heartbeat),
                              payload_length=42, crc32=0x12345678)
        encoded = WireCodec.encode_header(original)
        restored = WireCodec.decode_header(encoded)
        self.assertIsNotNone(restored)
        self.assertEqual(restored.magic, WIRE_MAGIC)
        self.assertEqual(restored.version, WIRE_VERSION)
        self.assertEqual(restored.payload_type, int(PayloadType.heartbeat))
        self.assertEqual(restored.payload_length, 42)
        self.assertEqual(restored.crc32, 0x12345678)

    def test_header_decode_rejects_short_buffer(self):
        self.assertIsNone(WireCodec.decode_header(b"\x00" * 10))


class TestCanonicalEventEncoding(unittest.TestCase):
    """Verify canonical event payload byte layout matches wire_v1.md spec."""

    def _make_known_event(self) -> CanonicalEvent:
        """Create an event with all fields set to known, verifiable values."""
        e = CanonicalEvent()
        e.magic = EVENT_MAGIC
        e.version = EVENT_VERSION
        e.struct_size = WIRE_PAYLOAD_SIZE
        e.event_id = 0x0102030405060708
        e.timestamp_ms = 0x1112131415161718
        e.monotonic_ns = 0x2122232425262728
        e.source = EventSource.wfp_sensor
        e.source_ip = 0xC0A80164  # 192.168.1.100
        e.source_port = 8080
        e.dest_ip = 0x0A000001  # 10.0.0.1
        e.dest_port = 443
        e.session_id = 0x3132333435363738
        e.protocol = 6  # TCP
        e.direction = 0  # inbound
        e.layer_id = 1  # WFP
        e.is_pipe = 0
        e.event_type = EventType.block
        e.severity = 3
        e.rule_id = 0xABCDEF01
        e.ruleset_version = 0x4142434445464748
        e.payload_length = 256
        e.payload_hash = 0x5152535455565758
        e.policy_action = PolicyAction.block
        e.enforcement_status = 1
        e.defcon_impact = 2
        e.context_flags = 0x61626364
        e.reserved = bytes(range(16))  # 0x00..0x0F
        return e

    def test_event_payload_size_is_109_bytes(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        self.assertEqual(len(encoded), WIRE_PAYLOAD_SIZE)
        self.assertEqual(len(encoded), 109)

    def test_event_magic_at_offset_0(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        # 0x41454731 LE = 31 47 45 41
        self.assertEqual(encoded[0], 0x31)
        self.assertEqual(encoded[1], 0x47)
        self.assertEqual(encoded[2], 0x45)
        self.assertEqual(encoded[3], 0x41)

    def test_event_version_at_offset_4(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        self.assertEqual(encoded[4], 1)
        self.assertEqual(encoded[5], 0)

    def test_event_struct_size_at_offset_6(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        # struct_size = 109 = 0x006D, LE = 6D 00
        self.assertEqual(encoded[6], 0x6D)
        self.assertEqual(encoded[7], 0x00)

    def test_event_id_at_offset_8_little_endian(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        # event_id = 0x0102030405060708, LE = 08 07 06 05 04 03 02 01
        self.assertEqual(encoded[8], 0x08)
        self.assertEqual(encoded[9], 0x07)
        self.assertEqual(encoded[10], 0x06)
        self.assertEqual(encoded[11], 0x05)
        self.assertEqual(encoded[12], 0x04)
        self.assertEqual(encoded[13], 0x03)
        self.assertEqual(encoded[14], 0x02)
        self.assertEqual(encoded[15], 0x01)

    def test_timestamp_ms_at_offset_16(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        self.assertEqual(encoded[16], 0x18)
        self.assertEqual(encoded[23], 0x11)

    def test_monotonic_ns_at_offset_24(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        self.assertEqual(encoded[24], 0x28)
        self.assertEqual(encoded[31], 0x21)

    def test_source_at_offset_32(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        # source = wfp_sensor = 1
        self.assertEqual(encoded[32], 1)

    def test_source_ip_at_offset_33(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        # source_ip = 0xC0A80164, LE = 64 01 A8 C0
        self.assertEqual(encoded[33], 0x64)
        self.assertEqual(encoded[34], 0x01)
        self.assertEqual(encoded[35], 0xA8)
        self.assertEqual(encoded[36], 0xC0)

    def test_source_port_at_offset_37(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        # source_port = 8080 = 0x1F90, LE = 90 1F
        self.assertEqual(encoded[37], 0x90)
        self.assertEqual(encoded[38], 0x1F)

    def test_dest_ip_at_offset_39(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        # dest_ip = 0x0A000001, LE = 01 00 00 0A
        self.assertEqual(encoded[39], 0x01)
        self.assertEqual(encoded[40], 0x00)
        self.assertEqual(encoded[41], 0x00)
        self.assertEqual(encoded[42], 0x0A)

    def test_dest_port_at_offset_43(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        # dest_port = 443 = 0x01BB, LE = BB 01
        self.assertEqual(encoded[43], 0xBB)
        self.assertEqual(encoded[44], 0x01)

    def test_session_id_at_offset_45(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        # session_id = 0x3132333435363738, LE = 38 37 36 35 34 33 32 31
        self.assertEqual(encoded[45], 0x38)
        self.assertEqual(encoded[52], 0x31)

    def test_protocol_at_offset_53(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        self.assertEqual(encoded[53], 6)

    def test_event_type_at_offset_57(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        # event_type = block = 0
        self.assertEqual(encoded[57], 0)
        self.assertEqual(encoded[58], 0)
        self.assertEqual(encoded[59], 0)
        self.assertEqual(encoded[60], 0)

    def test_rule_id_at_offset_62(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        # rule_id = 0xABCDEF01, LE = 01 EF CD AB
        self.assertEqual(encoded[62], 0x01)
        self.assertEqual(encoded[63], 0xEF)
        self.assertEqual(encoded[64], 0xCD)
        self.assertEqual(encoded[65], 0xAB)

    def test_reserved_at_offset_93(self):
        e = self._make_known_event()
        encoded = WireCodec.encode_event(e)
        # reserved = bytes(range(16)) = 0x00..0x0F
        for i in range(16):
            self.assertEqual(encoded[93 + i], i, f"reserved[{i}] mismatch")

    def test_event_round_trip_preserves_all_fields(self):
        original = self._make_known_event()
        encoded = WireCodec.encode_event(original)
        restored = WireCodec.decode_event(encoded)
        self.assertIsNotNone(restored)
        self.assertEqual(restored.event_id, original.event_id)
        self.assertEqual(restored.timestamp_ms, original.timestamp_ms)
        self.assertEqual(restored.monotonic_ns, original.monotonic_ns)
        self.assertEqual(restored.source, original.source)
        self.assertEqual(restored.source_ip, original.source_ip)
        self.assertEqual(restored.source_port, original.source_port)
        self.assertEqual(restored.dest_ip, original.dest_ip)
        self.assertEqual(restored.dest_port, original.dest_port)
        self.assertEqual(restored.session_id, original.session_id)
        self.assertEqual(restored.protocol, original.protocol)
        self.assertEqual(restored.event_type, original.event_type)
        self.assertEqual(restored.severity, original.severity)
        self.assertEqual(restored.rule_id, original.rule_id)
        self.assertEqual(restored.ruleset_version, original.ruleset_version)
        self.assertEqual(restored.payload_length, original.payload_length)
        self.assertEqual(restored.payload_hash, original.payload_hash)
        self.assertEqual(restored.policy_action, original.policy_action)
        self.assertEqual(restored.enforcement_status, original.enforcement_status)
        self.assertEqual(restored.defcon_impact, original.defcon_impact)
        self.assertEqual(restored.context_flags, original.context_flags)
        self.assertEqual(restored.reserved, original.reserved)

    def test_decode_rejects_wrong_magic(self):
        e = self._make_known_event()
        encoded = bytearray(WireCodec.encode_event(e))
        encoded[0] = 0x00
        self.assertIsNone(WireCodec.decode_event(bytes(encoded)))

    def test_decode_rejects_wrong_version(self):
        e = self._make_known_event()
        encoded = bytearray(WireCodec.encode_event(e))
        encoded[4] = 99
        self.assertIsNone(WireCodec.decode_event(bytes(encoded)))

    def test_decode_rejects_short_buffer(self):
        self.assertIsNone(WireCodec.decode_event(b"\x00" * 50))


class TestFullWireFrame(unittest.TestCase):
    """Verify full wire frame (header + payload) encoding."""

    def _make_event(self) -> CanonicalEvent:
        e = CanonicalEvent()
        e.event_id = 42
        e.source = EventSource.zig_core
        e.source_ip = 0xC0A80164
        e.source_port = 8080
        e.event_type = EventType.block
        e.severity = 3
        e.rule_id = 0x12345678
        e.payload_length = 256
        return e

    def test_frame_size_is_125_bytes(self):
        e = self._make_event()
        frame = WireCodec.encode_frame(e)
        self.assertEqual(len(frame), WIRE_FRAME_SIZE)
        self.assertEqual(len(frame), 125)

    def test_frame_header_magic_at_offset_0(self):
        e = self._make_event()
        frame = WireCodec.encode_frame(e)
        # wire magic 0x57455631, LE = 31 56 45 57
        self.assertEqual(frame[0], 0x31)
        self.assertEqual(frame[1], 0x56)
        self.assertEqual(frame[2], 0x45)
        self.assertEqual(frame[3], 0x57)

    def test_frame_payload_starts_at_offset_16(self):
        e = self._make_event()
        frame = WireCodec.encode_frame(e)
        # Canonical event magic 0x41454731, LE = 31 47 45 41
        self.assertEqual(frame[16], 0x31)
        self.assertEqual(frame[17], 0x47)
        self.assertEqual(frame[18], 0x45)
        self.assertEqual(frame[19], 0x41)

    def test_frame_round_trip(self):
        e = self._make_event()
        frame = WireCodec.encode_frame(e)
        decoded = WireCodec.decode_frame(frame)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.event_id, e.event_id)
        self.assertEqual(decoded.source_ip, e.source_ip)
        self.assertEqual(decoded.event_type, e.event_type)

    def test_frame_rejects_corrupted_crc(self):
        e = self._make_event()
        frame = bytearray(WireCodec.encode_frame(e))
        frame[20] ^= 0xFF  # Corrupt a payload byte
        self.assertIsNone(WireCodec.decode_frame(bytes(frame)))

    def test_frame_rejects_wrong_magic(self):
        e = self._make_event()
        frame = bytearray(WireCodec.encode_frame(e))
        frame[0] = 0x00
        self.assertIsNone(WireCodec.decode_frame(bytes(frame)))

    def test_frame_rejects_wrong_payload_type(self):
        e = self._make_event()
        frame = bytearray(WireCodec.encode_frame(e))
        frame[6] = 1  # command instead of event
        self.assertIsNone(WireCodec.decode_frame(bytes(frame)))

    def test_frame_rejects_wrong_payload_length(self):
        e = self._make_event()
        frame = bytearray(WireCodec.encode_frame(e))
        # Overwrite payload_length with wrong value
        struct.pack_into("<I", frame, 8, 200)
        self.assertIsNone(WireCodec.decode_frame(bytes(frame)))

    def test_frame_rejects_short_buffer(self):
        self.assertIsNone(WireCodec.decode_frame(b"\x00" * 10))


class TestCrc32Consistency(unittest.TestCase):
    """Verify CRC32 matches what other languages produce (IEEE 802.3 polynomial)."""

    def test_crc32_empty_payload(self):
        # CRC32 of empty input = 0x00000000 (after xor with 0xFFFFFFFF, then xor again)
        # Python's zlib.crc32(b'') = 0
        self.assertEqual(zlib.crc32(b"") & 0xFFFFFFFF, 0)

    def test_crc32_known_payload(self):
        # CRC32 of b"123456789" should be 0xCBF43926 (standard test vector)
        self.assertEqual(zlib.crc32(b"123456789") & 0xFFFFFFFF, 0xCBF43926)

    def test_frame_crc32_is_computed_over_payload_only(self):
        e = CanonicalEvent()
        e.event_id = 1
        e.source = EventSource.zig_core
        frame = WireCodec.encode_frame(e)
        # Decode header to get crc32 field
        header = WireCodec.decode_header(frame)
        self.assertIsNotNone(header)
        # Recompute crc32 over payload bytes only
        payload = frame[WIRE_HEADER_SIZE:WIRE_HEADER_SIZE + WIRE_PAYLOAD_SIZE]
        recomputed = zlib.crc32(payload) & 0xFFFFFFFF
        self.assertEqual(recomputed, header.crc32)


class TestAgainstZigBinaryVector(unittest.TestCase):
    """If tests/contracts/wire_event.bin exists, verify Python codec matches Zig output."""

    def test_matches_zig_wire_event_bin_if_present(self):
        vector_path = os.path.join(PROJECT_ROOT, "tests", "contracts", "wire_event.bin")
        if not os.path.exists(vector_path):
            self.skipTest(f"Test vector not found: {vector_path} (run generate_test_vectors.py first)")

        with open(vector_path, "rb") as f:
            zig_frame = f.read()

        # Decode the Zig-produced frame
        decoded = WireCodec.decode_frame(zig_frame)
        self.assertIsNotNone(decoded, "Python codec failed to decode Zig-produced wire_event.bin")

        # Re-encode with Python codec — bytes must match exactly
        python_frame = WireCodec.encode_frame(decoded)
        self.assertEqual(
            python_frame, zig_frame,
            "Python re-encoding does not match Zig output byte-for-byte"
        )

    def test_matches_zig_canonical_event_bin_if_present(self):
        vector_path = os.path.join(PROJECT_ROOT, "tests", "contracts", "canonical_event.bin")
        if not os.path.exists(vector_path):
            self.skipTest(f"Test vector not found: {vector_path}")

        with open(vector_path, "rb") as f:
            zig_payload = f.read()

        decoded = WireCodec.decode_event(zig_payload)
        self.assertIsNotNone(decoded, "Python codec failed to decode Zig-produced canonical_event.bin")

        python_payload = WireCodec.encode_event(decoded)
        self.assertEqual(
            python_payload, zig_payload,
            "Python re-encoding does not match Zig output byte-for-byte"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
