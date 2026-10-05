"""Python reference codec for the federation wire v1 (FED-P1B).

Independent implementation of src/federation/federation_codec.zig used
to pin the frozen golden vectors: this encoder must reproduce the
committed .bin bytes exactly, and this decoder must read them back.
Any wire change updates the Zig codec, this file, the generator, and
the vectors in the SAME patch (one schema, N codecs).

Frame: magic u32 LE ("AEGI"), version u8, msg_type u8, payload_len
u16 LE, crc32 u32 LE (IEEE/zlib) over the payload.
"""
from __future__ import annotations

import struct
import zlib

MAGIC = 0x41454749
VERSION = 1
HEADER_LEN = 12
MAX_PAYLOAD_SIZE = 4096 - HEADER_LEN


class FedWireError(ValueError):
    pass


def _blob_encode(raw: bytes) -> bytes:
    if len(raw) > 255:
        raise FedWireError("blob exceeds 255 bytes")
    return struct.pack("B", len(raw)) + raw


def _blob_decode(buf: bytes, off: int) -> tuple[bytes, int]:
    if off >= len(buf):
        raise FedWireError("truncated blob length")
    (n,) = struct.unpack_from("B", buf, off)
    off += 1
    end = off + n
    if end > len(buf):
        raise FedWireError("truncated blob body")
    return buf[off:end], end


def encode_message(msg: dict) -> bytes:
    p = b""
    p += struct.pack("<I", msg["from_node_id"])
    p += struct.pack("<I", msg["to_node_id"])
    p += struct.pack("<q", msg["timestamp_ns"])
    p += struct.pack("<I", msg["seq"])
    node = msg.get("node")
    if node is None:
        p += struct.pack("B", 0)
    else:
        p += struct.pack("B", 1)
        p += struct.pack("<I", node["node_id"])
        p += _blob_encode(node["name"])
        p += _blob_encode(node["endpoint"])
        p += struct.pack("B", node["role"])
        p += struct.pack("B", node["health"])
        p += struct.pack("<H", node["capacity"])
        p += struct.pack("<q", node["joined_ns"])
        p += struct.pack("<q", node["last_seen_ns"])
    inc = msg["incident"]
    p += bytes(inc["source_ip"])
    p += struct.pack("<H", inc["remote_port"])
    p += struct.pack("B", inc["proto"])
    p += struct.pack("B", inc["severity"])
    p += struct.pack("<f", inc["score"])
    p += _blob_encode(inc["label"])
    ti = msg.get("threat_intel")
    if ti is None:
        p += struct.pack("B", 0)
    else:
        p += struct.pack("B", 1)
        p += struct.pack("B", ti["kind"])
        p += bytes(ti["ip"])
        if len(ti["hash"]) != 16:
            raise FedWireError("threat hash must be 16 bytes")
        p += bytes(ti["hash"])
        p += _blob_encode(ti["domain"])
        p += struct.pack("<I", ti["source_node_id"])
        p += struct.pack("<q", ti["first_seen_ns"])
        p += struct.pack("B", ti["confidence"])
    p += struct.pack("<I", msg["leader_node_id"])
    if len(p) > MAX_PAYLOAD_SIZE:
        raise FedWireError("payload too large")
    header = struct.pack("<I", MAGIC)
    header += struct.pack("B", VERSION)
    header += struct.pack("B", msg["msg_type"])
    header += struct.pack("<H", len(p))
    header += struct.pack("<I", zlib.crc32(p) & 0xFFFFFFFF)
    return header + p


def decode_frame(data: bytes) -> dict:
    if len(data) < HEADER_LEN:
        raise FedWireError("frame shorter than header")
    magic, version, msg_type, pay_len, crc = struct.unpack_from("<IBBHI", data, 0)
    if magic != MAGIC:
        raise FedWireError("MagicMismatch")
    if version != VERSION:
        raise FedWireError("VersionMismatch")
    if len(data) < HEADER_LEN + pay_len:
        raise FedWireError("PayloadTruncated")
    payload = data[HEADER_LEN:HEADER_LEN + pay_len]
    if (zlib.crc32(payload) & 0xFFFFFFFF) != crc:
        raise FedWireError("CrcMismatch")
    if msg_type > 6:
        raise FedWireError("InvalidMsgType")
    off = 0

    def take(fmt: str):
        nonlocal off
        vals = struct.unpack_from(fmt, payload, off)
        off += struct.calcsize(fmt)
        return vals[0] if len(vals) == 1 else vals

    msg: dict = {
        "msg_type": msg_type,
        "from_node_id": take("<I"),
        "to_node_id": take("<I"),
        "timestamp_ns": take("<q"),
        "seq": take("<I"),
    }
    (has_node,) = struct.unpack_from("B", payload, off)
    off += 1
    if has_node == 1:
        node_id = take("<I")
        name, off = _blob_decode(payload, off)
        endpoint, off = _blob_decode(payload, off)
        role = take("B")
        health = take("B")
        capacity = take("<H")
        joined_ns = take("<q")
        last_seen_ns = take("<q")
        msg["node"] = {"node_id": node_id, "name": name,
                       "endpoint": endpoint, "role": role,
                       "health": health, "capacity": capacity,
                       "joined_ns": joined_ns,
                       "last_seen_ns": last_seen_ns}
    else:
        msg["node"] = None
    msg["incident"] = {
        "source_ip": list(payload[off:off + 4]),
        "remote_port": struct.unpack_from("<H", payload, off + 4)[0],
        "proto": payload[off + 6],
        "severity": payload[off + 7],
        "score": struct.unpack_from("<f", payload, off + 8)[0],
    }
    off += 12
    label, off = _blob_decode(payload, off)
    msg["incident"]["label"] = label
    (has_ti,) = struct.unpack_from("B", payload, off)
    off += 1
    if has_ti == 1:
        kind = payload[off]
        off += 1
        ip = list(payload[off:off + 4])
        off += 4
        h = bytes(payload[off:off + 16])
        off += 16
        domain, off = _blob_decode(payload, off)
        source_node_id = struct.unpack_from("<I", payload, off)[0]
        off += 4
        first_seen_ns = struct.unpack_from("<q", payload, off)[0]
        off += 8
        (confidence,) = struct.unpack_from("B", payload, off)
        off += 1
        msg["threat_intel"] = {"kind": kind, "ip": ip, "hash": h,
                               "domain": domain,
                               "source_node_id": source_node_id,
                               "first_seen_ns": first_seen_ns,
                               "confidence": confidence}
    else:
        msg["threat_intel"] = None
    msg["leader_node_id"] = struct.unpack_from("<I", payload, off)[0]
    return msg
