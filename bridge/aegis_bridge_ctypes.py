"""
aegis_bridge_ctypes.py — Python ↔ Native FFI Bridge (Cross-layer)

Provides ctypes-based access to:
  - Zig capture/analysis layer (aegis_capture.dll, aegis_analyze.dll)
  - Rust shield layer (aegis_shield.dll)
  - C++ IPC bridge (aegis_ipc.dll)
  - C++ packet parser (aegis_packet_parser.dll)
  - Go performance monitor (via named pipe)

All native calls go through this bridge with proper error handling
and type safety. The Python brain (windows_brain.py) uses this
bridge for all inter-layer communication.
"""

import ctypes
import logging
import struct
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aegis.bridge")

# ─── C-ABI Structure Definitions (matching kernel/Zig/Rust) ───

class AegisPktMetaC(ctypes.Structure):
    """Packet metadata — matches AegisPktMeta in Zig/Rust/C/C++.
    Includes Semi-NIDS fields (threat_score, confidence, risk_flags)
    that are set by the Rust correlation engine and read by the W!FP kernel driver.
    """
    _pack_ = 1
    _fields_ = [
        ("size",        ctypes.c_uint32),
        ("orig_len",    ctypes.c_uint32),
        ("timestamp",   ctypes.c_uint64),
        ("layer_id",    ctypes.c_uint16),
        ("direction",   ctypes.c_uint16),
        ("process_id",  ctypes.c_uint32),
        ("ip_proto",    ctypes.c_uint16),
        ("_pad",        ctypes.c_uint16),
        ("src_ip",      ctypes.c_uint32),
        ("dst_ip",      ctypes.c_uint32),
        ("src_port",    ctypes.c_uint16),
        ("dst_port",    ctypes.c_uint16),
        # Semi-NIDS fields (set by Rust correlation, read by WFP kernel)
        ("threat_score", ctypes.c_int32),    # 0-100 (x10 fixed-point: 600 = 60.0)
        ("confidence",   ctypes.c_uint8),    # 0=Unknown,1=Low,2=Medium,3=High,4=Critical
        ("risk_flags",   ctypes.c_uint32),   # Bitfield of matched rules
    ]


# ─── Semi-NIDS Stats Structure (matches Rust SemiNidsStats #[repr(C)]) ───

class SemiNidsStatsC(ctypes.Structure):
    """Engine statistics — matches SemiNidsStats in Rust semi_nids.rs.

    Fields (must match Rust layout exactly for correct FFI):
      total_evaluated: u64, total_passed: u64, total_alerted: u64,
      total_blocked: u64, total_rate_limited: u64, total_fail_open_passes: u64,
      total_human_decisions: u64, permanent_blocks: u32, temporary_blocks: u32,
      fail_open_active: bool, load_state: u8 (LoadState), current_pps: u64
    """
    _pack_ = 1
    _fields_ = [
        ("total_evaluated",      ctypes.c_uint64),
        ("total_passed",         ctypes.c_uint64),
        ("total_alerted",        ctypes.c_uint64),
        ("total_blocked",        ctypes.c_uint64),
        ("total_rate_limited",   ctypes.c_uint64),
        ("total_fail_open_passes", ctypes.c_uint64),
        ("total_human_decisions", ctypes.c_uint64),
        ("permanent_blocks",     ctypes.c_uint32),
        ("temporary_blocks",     ctypes.c_uint32),
        ("fail_open_active",     ctypes.c_bool),
        ("load_state",           ctypes.c_uint8),   # LoadState enum: 0-3
        ("current_pps",          ctypes.c_uint64),
    ]


class AegisFileEventC(ctypes.Structure):
    """File event — matches AegisFileEvent in C++."""
    _pack_ = 1
    _fields_ = [
        ("size",        ctypes.c_uint32),
        ("timestamp",   ctypes.c_uint64),
        ("pid",         ctypes.c_uint32),
        ("tid",         ctypes.c_uint32),
        ("event_type",  ctypes.c_uint16),
        ("file_size_hi", ctypes.c_uint16),
        ("file_size_lo", ctypes.c_uint32),
        ("path_len",    ctypes.c_uint16),
        ("_pad",        ctypes.c_uint16),
        ("path",        ctypes.c_wchar * 520),
    ]


class AegisRingHeaderC(ctypes.Structure):
    """Ring buffer header — matches AegisRingHeader in C."""
    _pack_ = 1
    _fields_ = [
        ("write_pos",     ctypes.c_uint32),
        ("read_pos",      ctypes.c_uint32),
        ("capacity",      ctypes.c_uint32),
        ("packet_count",  ctypes.c_uint32),
        ("dropped_count", ctypes.c_uint32),
    ]


# ─── Native Library Loader ───

class NativeLibrary:
    """Thread-safe loader for a native shared library with C-ABI."""

    def __init__(self, name: str, search_paths: list[Path] = None):
        self.name = name
        self._lib: Optional[ctypes.CDLL] = None
        self._lock = threading.Lock()
        self._search_paths = search_paths or [
            Path("."), Path("kernel/ipc"), Path("shield_rust/target/release"),
            Path("capture_zig/zig-out"), Path("kernel/packet_parser"),
        ]

    def load(self) -> bool:
        """Attempt to load the library from search paths."""
        with self._lock:
            if self._lib is not None:
                return True

            for path in self._search_paths:
                try:
                    full_path = path / self.name
                    self._lib = ctypes.CDLL(str(full_path))
                    logger.info(f"Loaded native library: {full_path}")
                    return True
                except OSError:
                    continue

            # Try system library path
            try:
                self._lib = ctypes.CDLL(self.name)
                logger.info(f"Loaded system library: {self.name}")
                return True
            except OSError:
                pass

            logger.warning(f"Failed to load native library: {self.name}")
            return False

    @property
    def lib(self) -> Optional[ctypes.CDLL]:
        return self._lib

    def is_loaded(self) -> bool:
        return self._lib is not None


# ─── Bridge Instances ───

ipc_bridge      = NativeLibrary("aegis_ipc.dll")
packet_parser   = NativeLibrary("aegis_packet_parser.dll")
shield_bridge   = NativeLibrary("aegis_shield.dll")
capture_bridge  = NativeLibrary("aegis_capture.dll")


# ─── IPC Bridge Functions ───

def ipc_init() -> bool:
    """Initialize IPC bridge — map kernel ring buffers."""
    if not ipc_bridge.load():
        return False
    ipc_bridge.lib.aegis_ipc_init.restype = ctypes.c_int32
    rc = ipc_bridge.lib.aegis_ipc_init()
    return rc == 0


def ipc_read_packet(meta_buf: AegisPktMetaC, payload_buf: ctypes.Array,
                    buf_size: ctypes.POINTER) -> int:
    """Read next packet from WFP ring buffer."""
    if not ipc_bridge.is_loaded():
        return -1
    ipc_bridge.lib.aegis_ipc_read_packet.restype = ctypes.c_int32
    return ipc_bridge.lib.aegis_ipc_read_packet(
        ctypes.byref(meta_buf), payload_buf, buf_size
    )


def ipc_get_stats() -> dict:
    """Get WFP ring buffer statistics."""
    if not ipc_bridge.is_loaded():
        return {}
    packets = ctypes.c_uint32()
    dropped = ctypes.c_uint32()
    ipc_bridge.lib.aegis_ipc_get_stats.restype = ctypes.c_int32
    ipc_bridge.lib.aegis_ipc_get_stats(
        ctypes.byref(packets), ctypes.byref(dropped)
    )
    return {"packets": packets.value, "dropped": dropped.value}


# ─── Shield Bridge Functions ───

def shield_init() -> bool:
    """Initialize Rust memory safety shield."""
    if not shield_bridge.load():
        return False
    shield_bridge.lib.aegis_shield_init.restype = ctypes.c_int32
    return shield_bridge.lib.aegis_shield_init() == 0


def shield_submit_packet(meta: AegisPktMetaC, payload: bytes,
                         pattern_ids: list[int]) -> int:
    """Submit matched packet to Rust shield for forensic hashing."""
    if not shield_bridge.is_loaded():
        return -1

    # Convert pattern IDs to C array
    n = len(pattern_ids)
    c_ids = (ctypes.c_uint32 * n)(*pattern_ids) if n > 0 else None

    shield_bridge.lib.aegis_shield_submit_packet.restype = ctypes.c_int32
    return shield_bridge.lib.aegis_shield_submit_packet(
        ctypes.byref(meta), payload, len(payload),
        c_ids, n
    )


def shield_get_forensic_hash() -> Optional[bytes]:
    """Get the latest forensic SHA-256 hash from Rust shield."""
    if not shield_bridge.is_loaded():
        return None

    hash_buf = (ctypes.c_uint8 * 32)()
    shield_bridge.lib.aegis_shield_get_forensic_hash.restype = ctypes.c_int32
    rc = shield_bridge.lib.aegis_shield_get_forensic_hash(hash_buf)
    if rc != 0:
        return None
    return bytes(hash_buf)


def shield_shutdown() -> None:
    """Shutdown Rust shield and release resources."""
    if shield_bridge.is_loaded():
        shield_bridge.lib.aegis_shield_shutdown()


# ─── Semi-NIDS Bridge Functions (Property 1, 2, 3) ───

def semi_nids_init() -> bool:
    """Initialize Rust Semi-NIDS engine (adaptive drop + fail-open + human-in-loop)."""
    if not shield_bridge.load():
        return False
    shield_bridge.lib.aegis_semi_nids_init.restype = ctypes.c_int32
    return shield_bridge.lib.aegis_semi_nids_init() == 0


def semi_nids_evaluate(src_ip: int, dst_ip: int, src_port: int, dst_port: int,
                       ip_proto: int, threat_score: float, confidence: int,
                       risk_flags: int, process_id: int) -> int:
    """Evaluate threat → returns SemiNidsDecision (0-5).

    Decision codes:
      0=Pass, 1=AlertOnly, 2=RateLimit, 3=Block, 4=BlockAndPreserve, 5=PendingHuman

    Rust FFI: aegis_semi_nids_evaluate(src_ip, dst_ip, src_port, dst_port,
                                       ip_proto, threat_score, confidence,
                                       risk_flags, process_id) -> u8
    """
    if not shield_bridge.is_loaded():
        return 0  # Pass
    shield_bridge.lib.aegis_semi_nids_evaluate.restype = ctypes.c_uint8
    shield_bridge.lib.aegis_semi_nids_evaluate.argtypes = [
        ctypes.c_uint32,  # src_ip
        ctypes.c_uint32,  # dst_ip
        ctypes.c_uint16,  # src_port
        ctypes.c_uint16,  # dst_port
        ctypes.c_uint8,   # ip_proto
        ctypes.c_double,  # threat_score
        ctypes.c_uint8,   # confidence
        ctypes.c_uint32,  # risk_flags
        ctypes.c_uint32,  # process_id
    ]
    return shield_bridge.lib.aegis_semi_nids_evaluate(
        ctypes.c_uint32(src_ip), ctypes.c_uint32(dst_ip),
        ctypes.c_uint16(src_port), ctypes.c_uint16(dst_port),
        ctypes.c_uint8(ip_proto),
        ctypes.c_double(threat_score),
        ctypes.c_uint8(confidence),
        ctypes.c_uint32(risk_flags),
        ctypes.c_uint32(process_id),
    )


def semi_nids_set_policy(alert_id: int, decision: int) -> int:
    """Human sets policy on a pending alert (Property 3: Interactive Control Loop).

    decision codes: 1=Block, 2=BlockTemp, 3=Whitelist, 4=Ignore, 5=Escalate
    """
    if not shield_bridge.is_loaded():
        return -1
    shield_bridge.lib.aegis_semi_nids_set_policy.restype = ctypes.c_int32
    return shield_bridge.lib.aegis_semi_nids_set_policy(
        ctypes.c_uint64(alert_id), ctypes.c_uint8(decision)
    )


def semi_nids_get_pending_count() -> int:
    """Get number of alerts pending human decision."""
    if not shield_bridge.is_loaded():
        return 0
    shield_bridge.lib.aegis_semi_nids_get_pending_count.restype = ctypes.c_uint32
    return shield_bridge.lib.aegis_semi_nids_get_pending_count()


def semi_nids_block_ip(ip: int, reason: int = 0) -> int:
    """Block an IP immediately at kernel level.

    Rust FFI: aegis_semi_nids_block_ip(ip: u32, reason: u32) -> i32
    """
    if not shield_bridge.is_loaded():
        return -1
    shield_bridge.lib.aegis_semi_nids_block_ip.restype = ctypes.c_int32
    shield_bridge.lib.aegis_semi_nids_block_ip.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32
    ]
    return shield_bridge.lib.aegis_semi_nids_block_ip(
        ctypes.c_uint32(ip), ctypes.c_uint32(reason)
    )


def semi_nids_unblock_ip(ip: int) -> int:
    """Remove IP from block list (whitelist)."""
    if not shield_bridge.is_loaded():
        return -1
    shield_bridge.lib.aegis_semi_nids_unblock_ip.restype = ctypes.c_int32
    return shield_bridge.lib.aegis_semi_nids_unblock_ip(ctypes.c_uint32(ip))


def semi_nids_update_load(cpu_pct: int, queue_pct: int, pps: int) -> None:
    """Update load metrics from Go perf monitor (Property 2: Fail-Open)."""
    if not shield_bridge.is_loaded():
        return
    shield_bridge.lib.aegis_semi_nids_update_load(
        ctypes.c_uint8(cpu_pct), ctypes.c_uint8(queue_pct), ctypes.c_uint64(pps)
    )


def semi_nids_fail_open_status() -> dict:
    """Query fail-open status (Property 2: Graceful Degradation).

    Rust FFI: aegis_semi_nids_fail_open_status(out_active, out_cpu_pct, out_queue_pct) -> u8
    Returns load_state (0-3) + active/cpu/queue details.
    """
    if not shield_bridge.is_loaded():
        return {"load_state": 0, "active": False, "cpu_pct": 0, "queue_pct": 0}
    out_active = ctypes.c_bool()
    out_cpu = ctypes.c_uint8()
    out_queue = ctypes.c_uint8()
    shield_bridge.lib.aegis_semi_nids_fail_open_status.restype = ctypes.c_uint8
    shield_bridge.lib.aegis_semi_nids_fail_open_status.argtypes = [
        ctypes.POINTER(ctypes.c_bool),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    load_state = shield_bridge.lib.aegis_semi_nids_fail_open_status(
        ctypes.byref(out_active), ctypes.byref(out_cpu), ctypes.byref(out_queue)
    )
    return {
        "load_state": load_state,
        "active": out_active.value,
        "cpu_pct": out_cpu.value,
        "queue_pct": out_queue.value,
    }


def semi_nids_get_pending(index: int) -> dict:
    """Get pending alert details by index (for console/UI polling).

    Rust FFI: aegis_semi_nids_get_pending(index, out_alert_id, out_src_ip,
                                           out_threat_score, out_confidence,
                                           out_decision) -> i32
    """
    if not shield_bridge.is_loaded():
        return {}
    out_alert_id = ctypes.c_uint64(0)
    out_src_ip = ctypes.c_uint32(0)
    out_threat_score = ctypes.c_double(0.0)
    out_confidence = ctypes.c_uint8(0)
    out_decision = ctypes.c_uint8(0)
    shield_bridge.lib.aegis_semi_nids_get_pending.restype = ctypes.c_int32
    shield_bridge.lib.aegis_semi_nids_get_pending.argtypes = [
        ctypes.c_uint32,                       # index
        ctypes.POINTER(ctypes.c_uint64),       # out_alert_id
        ctypes.POINTER(ctypes.c_uint32),       # out_src_ip
        ctypes.POINTER(ctypes.c_double),       # out_threat_score
        ctypes.POINTER(ctypes.c_uint8),        # out_confidence
        ctypes.POINTER(ctypes.c_uint8),        # out_decision
    ]
    rc = shield_bridge.lib.aegis_semi_nids_get_pending(
        ctypes.c_uint32(index),
        ctypes.byref(out_alert_id), ctypes.byref(out_src_ip),
        ctypes.byref(out_threat_score), ctypes.byref(out_confidence),
        ctypes.byref(out_decision),
    )
    if rc != 0:
        return {}
    return {
        "alert_id": out_alert_id.value,
        "src_ip": out_src_ip.value,
        "threat_score": out_threat_score.value,
        "confidence": out_confidence.value,
        "decision": out_decision.value,
    }


def semi_nids_get_stats() -> dict:
    """Get Semi-NIDS engine statistics.

    Rust FFI: aegis_semi_nids_get_stats(out_stats: *mut SemiNidsStats) -> i32
    Passes a single struct pointer matching Rust SemiNidsStats layout.
    """
    if not shield_bridge.is_loaded():
        return {}
    stats = SemiNidsStatsC()
    shield_bridge.lib.aegis_semi_nids_get_stats.restype = ctypes.c_int32
    shield_bridge.lib.aegis_semi_nids_get_stats.argtypes = [
        ctypes.POINTER(SemiNidsStatsC)
    ]
    rc = shield_bridge.lib.aegis_semi_nids_get_stats(ctypes.byref(stats))
    if rc != 0:
        return {}
    return {
        "total_evaluated":      stats.total_evaluated,
        "total_passed":        stats.total_passed,
        "total_alerted":       stats.total_alerted,
        "total_blocked":       stats.total_blocked,
        "total_rate_limited":  stats.total_rate_limited,
        "total_fail_open_passes": stats.total_fail_open_passes,
        "total_human_decisions": stats.total_human_decisions,
        "permanent_blocks":    stats.permanent_blocks,
        "temporary_blocks":    stats.temporary_blocks,
        "fail_open_active":   stats.fail_open_active,
        "load_state":         stats.load_state,
        "current_pps":        stats.current_pps,
    }


def semi_nids_maintenance() -> int:
    """Run periodic maintenance (expire temp blocks, clean up).

    Rust FFI: aegis_semi_nids_maintenance() -> u32
    Returns number of expired temp blocks.
    """
    if not shield_bridge.is_loaded():
        return 0
    shield_bridge.lib.aegis_semi_nids_maintenance.restype = ctypes.c_uint32
    return shield_bridge.lib.aegis_semi_nids_maintenance()


def semi_nids_shutdown() -> None:
    """Shutdown Semi-NIDS engine and release resources.

    Rust FFI: aegis_semi_nids_shutdown() (returns void)
    """
    if shield_bridge.is_loaded():
        shield_bridge.lib.aegis_semi_nids_shutdown.restype = None
        shield_bridge.lib.aegis_semi_nids_shutdown()


# ─── Initialization ───

def init_all() -> bool:
    """Initialize all native bridges including Semi-NIDS engine."""
    success = True
    if not ipc_init():
        logger.warning("IPC bridge init failed")
        success = False
    if not shield_init():
        logger.warning("Shield bridge init failed")
        success = False
    if not semi_nids_init():
        logger.warning("Semi-NIDS engine init failed")
        # Not fatal — system can operate in legacy mode
    return success


def shutdown_all() -> None:
    """Shutdown all native bridges."""
    semi_nids_shutdown()
    shield_shutdown()


# ─── Correlation Engine Bridge Functions ───

def correlation_init() -> bool:
    """Initialize Rust cross-vector correlation engine."""
    if not shield_bridge.load():
        return False
    shield_bridge.lib.aegis_correlation_init.restype = ctypes.c_int32
    return shield_bridge.lib.aegis_correlation_init() == 0


def correlation_update_load(pps: int) -> None:
    """Update correlation engine with current PPS from Go perf monitor.

    Rust FFI: aegis_correlation_update_load(pps: u64)
    """
    if shield_bridge.is_loaded():
        shield_bridge.lib.aegis_correlation_update_load.restype = None
        shield_bridge.lib.aegis_correlation_update_load.argtypes = [ctypes.c_uint64]
        shield_bridge.lib.aegis_correlation_update_load(ctypes.c_uint64(pps))


def correlation_shutdown() -> None:
    """Shutdown correlation engine and release resources.

    Rust FFI: aegis_correlation_shutdown()
    """
    if shield_bridge.is_loaded():
        shield_bridge.lib.aegis_correlation_shutdown.restype = None
        shield_bridge.lib.aegis_correlation_shutdown()
