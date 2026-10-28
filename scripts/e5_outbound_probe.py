"""E5 outbound-capture probe (elevated, read-only over the bridge).

Reads IOCTL_AEGIS_GET_STATS before/after an operator traffic burst, then
drains whatever rows are in the 2 MB ring and counts them by the record's
direction byte (0=inbound, 1=outbound, O2 header). Writes an evidence JSON
next to itself. Any rows drained are reported explicitly (the daemon's own
telemetry loop drains constantly, so this probe races benignly for a small
window).
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import platform
import socket
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BRIDGE = REPO / "build" / "Release" / "aegis_wfp_user.dll"
OUT = REPO / "admin-evidence" / "e5-host-proof-20261026" / "e5b-outbound-probe.json"

CLASS_S = ctypes.Structure


class RingStats(CLASS_S):
    _pack_ = 1
    _fields_ = [
        ("total_events_written", ctypes.c_uint32),
        ("total_drops", ctypes.c_uint32),
        ("total_bytes_written", ctypes.c_uint32),
        ("total_bytes_read", ctypes.c_uint32),
        ("current_used_bytes", ctypes.c_uint32),
        ("padding", ctypes.c_uint32),
    ]


class EventHeader(CLASS_S):
    _pack_ = 1
    _fields_ = [
        ("event_type", ctypes.c_uint32),
        ("source_ip", ctypes.c_uint32),
        ("dest_ip", ctypes.c_uint32),
        ("source_port", ctypes.c_uint16),
        ("dest_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("direction", ctypes.c_uint8),
        ("layer_id", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
        ("payload_length", ctypes.c_uint32),
        ("rule_id", ctypes.c_uint32),
        ("severity", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("reserved2", ctypes.c_uint32),
        ("timestamp", ctypes.c_uint64),
    ]

    def as_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "src": inet(self.source_ip),
            "dst": inet(self.dest_ip),
            "sport": self.source_port,
            "dport": self.dest_port,
            "proto": self.protocol,
            "direction": self.direction,
            "payload_len": self.payload_length,
            "timestamp": self.timestamp,
        }


def inet(v: int) -> str:
    # IPv4 stored in network byte order -> dotted quad
    return socket.inet_ntoa(struct.pack(">I", v))


STRIDE = ctypes.sizeof(EventHeader)
assert STRIDE == 48, STRIDE


def main() -> int:
    dll = ctypes.WinDLL(str(BRIDGE), use_last_error=True)
    dll.aegis_wfp_ioctl_open.restype = ctypes.c_int
    dll.aegis_wfp_ioctl_get_stats.argtypes = [ctypes.POINTER(RingStats)]
    dll.aegis_wfp_ioctl_get_stats.restype = ctypes.c_int
    dll.aegis_wfp_ioctl_read_events.restype = ctypes.c_int
    dll.aegis_wfp_ioctl_close.restype = ctypes.c_int

    doc: dict = {
        "bridge": str(BRIDGE),
        "elevated": bool(ctypes.windll.shell32.IsUserAnAdmin()),
        "stride": STRIDE,
        "python": platform.python_version(),
        "phases": [],
    }

    rc = dll.aegis_wfp_ioctl_open()
    doc["open_rc"] = rc
    if rc != 0:
        doc["error"] = f"open failed; GetLastError={ctypes.get_last_error()}"
        OUT.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        print(json.dumps(doc, indent=2))
        return 1

    def stats() -> dict | None:
        s = RingStats()
        if dll.aegis_wfp_ioctl_get_stats(ctypes.byref(s)) != 0:
            return None
        return {
            "written": s.total_events_written,
            "drops": s.total_drops,
            "bytes_written": s.total_bytes_written,
            "bytes_read": s.total_bytes_read,
            "used": s.current_used_bytes,
        }

    def drain_phase(label: str, seconds: float) -> dict:
        import time
        phase: dict = {"label": label, "stats_before": stats(), "drained": STRIDE and []}
        counts = {0: 0, 1: 0}
        samples = {0: [], 1: []}
        deadline = time.time() + seconds
        buf = (ctypes.c_char * (STRIDE * 64))()
        by = ctypes.c_uint32(0)
        while time.time() < deadline:
            dll.aegis_wfp_ioctl_read_events(buf, STRIDE * 64, ctypes.byref(by))
            n = by.value // STRIDE
            for i in range(n):
                rec = EventHeader.from_buffer_copy(bytes(buf[i * STRIDE:(i + 1) * STRIDE]))
                d = rec.direction
                counts[d] = counts.get(d, 0) + 1
                if len(samples.setdefault(d, [])) < 5:
                    samples[d].append(rec.as_dict())
            if n == 0:
                time.sleep(0.02)
        phase["stats_after"] = stats()
        phase["count_by_direction"] = {"inbound(0)": counts[0], "outbound(1)": counts[1]}
        phase["samples_by_direction"] = {
            "inbound(0)": samples[0], "outbound(1)": samples[1],
        }
        doc["phases"].append(phase)
        return phase

    drain_phase("baseline_idle", 2.0)

    # Operator traffic burst: a handful of real outbound connections so the
    # outbound transport classify has live rows to copy.
    hosts = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    resolved: list[str] = []
    for h in hosts:
        try:
            con = socket.create_connection((h, 443), timeout=3)
            con.close()
            resolved.append(f"{h}:443 ok")
        except OSError as exc:
            resolved.append(f"{h}:443 skip ({exc})")
    try:
        socket.getaddrinfo("example.com", 443)
        resolved.append("dns example.com ok")
    except OSError as exc:
        resolved.append(f"dns example.com skip ({exc})")
    doc["traffic_burst"] = resolved

    drain_phase("burst_after_outbound_traffic", 6.0)

    dll.aegis_wfp_ioctl_close()
    OUT.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(json.dumps(doc["phases"][1]["count_by_direction"], indent=2)
          if len(doc["phases"]) > 1 else json.dumps(doc, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
