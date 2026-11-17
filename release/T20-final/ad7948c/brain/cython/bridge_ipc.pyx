"""bridge_ipc.pyx — T3-BRIDGE-026 Cython port of the C++ IPC Bridge binding.

Standing rule: Python talks to C through Cython, never ctypes as the
primary path. This module replaces `bridge/aegis_bridge_ctypes.py`'s
ctypes layer with a Cython module that resolves the SAME `aegis_ipc.dll`
exports at runtime (LoadLibrary, no link-time dependency) and exposes
the SAME Python API with byte-identical fallback semantics:

  - DLL/fn absent  -> init returns -1, push returns -1, pop returns None,
                      counts return 0, DEFCON reads SAFE/5, block returns -1.
  - No enforcement claim is ever manufactured here: block/unblock return
    exactly what the DLL returns (fail-closed -2 lives in C++), or -1
    when there is no DLL to ask. NEVER policy, NEVER PEP.

`bridge/aegis_bridge_ctypes.py` delegates to this module when the .pyd
is importable and keeps its ctypes code as the fallback otherwise.

Build: `cd brain/cython && python setup.py build_ext --inplace`
(kernel32 is default-linked on Windows; the bridge DLL itself is loaded
at runtime, never linked).
"""

import os

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t

cdef extern from "windows.h":
    ctypedef void* HMODULE
    ctypedef void* FARPROC
    HMODULE LoadLibraryA(const char* lpLibFileName)
    FARPROC GetProcAddress(HMODULE hModule, const char* lpProcName)
    int FreeLibrary(HMODULE hLibModule)

# --- Packed ABI structs (mirror aegis_ipc.hpp #pragma pack(1)) ---
cdef packed struct CEvent:
    uint32_t event_type
    uint32_t source_ip
    uint32_t dest_ip
    uint16_t source_port
    uint16_t dest_port
    uint8_t protocol
    uint8_t direction
    uint8_t layer_id
    uint8_t tier_result
    uint32_t payload_length
    uint32_t rule_id
    uint32_t severity
    uint32_t reserved
    uint64_t timestamp
    uint32_t source_pid
    uint32_t defcon_impact
    uint64_t event_id
    uint16_t schema_version
    uint8_t confidence
    uint8_t provenance
    uint32_t parent_pid
    uint32_t evidence_offset
    uint32_t evidence_length

cdef packed struct CCommand:
    uint32_t command_id
    uint32_t target_subsystem
    uint32_t payload_size
    uint32_t response_expected
    uint64_t timestamp

IPC_EVENT_SIZE = sizeof(CEvent)
IPC_COMMAND_SIZE = sizeof(CCommand)

# --- DLL function pointer types (extern "C", cdecl).
# Stored as void* globals (Cython rejects function-pointer-typed module
# variables); cast at each call site.
ctypedef int (*fn_init_t)()
ctypedef int (*fn_push_t)(const CEvent* event)
ctypedef int (*fn_pop_t)(CEvent* event)
ctypedef unsigned char (*fn_defcon_t)()
ctypedef void (*fn_update_defcon_t)(unsigned int c, unsigned int b,
                                    unsigned int k, unsigned int t)
ctypedef int (*fn_block_t)(unsigned int ip)
ctypedef unsigned int (*fn_count_t)()
ctypedef const char* (*fn_label_t)()

cdef HMODULE _dll = NULL
cdef object _dll_path = None
cdef void* _f_init = NULL
cdef void* _f_shutdown = NULL
cdef void* _f_push = NULL
cdef void* _f_pop = NULL
cdef void* _f_defcon = NULL
cdef void* _f_update = NULL
cdef void* _f_block = NULL
cdef void* _f_unblock = NULL
cdef void* _f_events = NULL
cdef void* _f_dropped = NULL
cdef void* _f_label = NULL
cdef void* _f_desc = NULL


cdef void _load():
    """Resolve aegis_ipc.dll once (same search order as the ctypes shim)."""
    global _dll, _f_init, _f_shutdown, _f_push, _f_pop, _f_defcon
    global _f_update, _f_block, _f_unblock, _f_events, _f_dropped
    global _f_label, _f_desc
    base = os.path.join(os.path.dirname(__file__), "..", "..", "bridge")
    candidates = [
        os.path.join(base, "aegis_ipc.dll"),
        os.path.join(base, "..", "dist", "aegis_ipc.dll"),
        os.path.join(base, "..", "build", "Release", "aegis_ipc.dll"),
        os.path.join(base, "..", "build", "Debug", "aegis_ipc.dll"),
        os.path.join(base, "..", "build", "aegis_ipc.dll"),
        os.path.join(base, "..", "target", "release", "aegis_ipc.dll"),
        "aegis_ipc.dll",
    ]
    for path in candidates:
        apath = os.path.abspath(path)
        handle = LoadLibraryA(apath.encode("utf-8"))
        if handle != NULL:
            _dll = handle
            global _dll_path
            _dll_path = apath
            break
    if _dll == NULL:
        return
    _f_init = GetProcAddress(_dll, b"aegis_bridge_init")
    _f_shutdown = GetProcAddress(_dll, b"aegis_bridge_shutdown")
    _f_push = GetProcAddress(_dll, b"aegis_bridge_push_event")
    _f_pop = GetProcAddress(_dll, b"aegis_bridge_pop_event")
    _f_defcon = GetProcAddress(_dll, b"aegis_bridge_get_defcon")
    _f_update = GetProcAddress(_dll, b"aegis_bridge_update_defcon")
    _f_block = GetProcAddress(_dll, b"aegis_bridge_block_ip")
    _f_unblock = GetProcAddress(_dll, b"aegis_bridge_unblock_ip")
    _f_events = GetProcAddress(_dll, b"aegis_bridge_get_event_count")
    _f_dropped = GetProcAddress(_dll, b"aegis_bridge_get_dropped_count")
    _f_label = GetProcAddress(_dll, b"aegis_bridge_get_defcon_label")
    _f_desc = GetProcAddress(_dll, b"aegis_bridge_get_defcon_description")


_load()


def is_available():
    """True when aegis_ipc.dll was found and loaded."""
    return _dll != NULL


def dll_path():
    """Absolute path of the loaded bridge DLL (None when standalone)."""
    return _dll_path


def resolved_symbols():
    """Debuggability: which ABI symbols resolved (True/False each)."""
    return {
        "init": _f_init != NULL,
        "shutdown": _f_shutdown != NULL,
        "push": _f_push != NULL,
        "pop": _f_pop != NULL,
        "defcon": _f_defcon != NULL,
        "update": _f_update != NULL,
        "block": _f_block != NULL,
        "unblock": _f_unblock != NULL,
        "events": _f_events != NULL,
        "dropped": _f_dropped != NULL,
        "label": _f_label != NULL,
        "desc": _f_desc != NULL,
    }


# --- Pure-Python surface (no C authority: labels, consts, decisions) ---
DEFCON_1_MAXIMUM = 1
DEFCON_2_SEVERE = 2
DEFCON_3_HIGH = 3
DEFCON_4_ELEVATED = 4
DEFCON_5_SAFE = 5

DEFCON_LABELS = {1: "MAXIMUM", 2: "SEVERE", 3: "HIGH", 4: "ELEVATED", 5: "SAFE"}
DEFCON_DESCRIPTIONS = {
    1: "10+ critical alerts OR 5+ blocked IPs OR kernel-level threats detected",
    2: "5+ critical alerts OR 3+ blocked IPs — active threat campaign",
    3: "5+ alerts OR 1+ critical — significant threat activity",
    4: "1-5 alerts — low-level threat activity observed",
    5: "No alerts — all systems nominal",
}


class BridgeEvent:
    """Attribute-compatible stand-in for the ctypes AegisIpcEvent struct."""

    def __init__(self):
        self.event_type = 0
        self.source_ip = 0
        self.dest_ip = 0
        self.source_port = 0
        self.dest_port = 0
        self.protocol = 0
        self.direction = 0
        self.layer_id = 0
        self.tier_result = 0
        self.payload_length = 0
        self.rule_id = 0
        self.severity = 0
        self.reserved = 0
        self.timestamp = 0
        self.source_pid = 0
        self.defcon_impact = 0
        self.event_id = 0
        self.schema_version = 0
        self.confidence = 0
        self.provenance = 0
        self.parent_pid = 0
        self.evidence_offset = 0
        self.evidence_length = 0


cdef void _fill_event(CEvent* ev, unsigned int event_type, unsigned int src_ip,
                      unsigned int dst_ip, unsigned int src_port, unsigned int dst_port,
                      unsigned int protocol, unsigned int tier, unsigned int rule,
                      unsigned int sev, unsigned int direction):
    ev.event_type = event_type
    ev.source_ip = src_ip
    ev.dest_ip = dst_ip
    ev.source_port = <uint16_t>src_port
    ev.dest_port = <uint16_t>dst_port
    ev.protocol = <uint8_t>protocol
    ev.direction = <uint8_t>direction
    ev.layer_id = <uint8_t>(0 if event_type == 0 else event_type)
    ev.tier_result = <uint8_t>tier
    ev.payload_length = 0
    ev.rule_id = rule
    ev.severity = sev
    ev.reserved = 0
    ev.timestamp = 0
    ev.source_pid = 0
    ev.defcon_impact = sev if sev >= 3 else 4
    ev.event_id = 0
    ev.schema_version = 0
    ev.confidence = 0
    ev.provenance = 0
    ev.parent_pid = 0
    ev.evidence_offset = 0
    ev.evidence_length = 0


def _ip_to_int(ip_string):
    try:
        parts = ip_string.split(".")
        if len(parts) != 4:
            return 0
        return ((int(parts[0]) << 24) | (int(parts[1]) << 16) |
                (int(parts[2]) << 8) | int(parts[3])) & 0xFFFFFFFF
    except (ValueError, IndexError, AttributeError):
        return 0


def bridge_init():
    if _f_init == NULL:
        return -1
    return (<fn_init_t>_f_init)()


def bridge_shutdown():
    if _f_shutdown == NULL:
        return -1
    return (<fn_init_t>_f_shutdown)()


def _rule_to_u32(rule_id):
    """Map a rule ID to its wire u32.

    Integers pass through; digit strings/floats truncate via int() (legacy
    shim behavior); anything else (e.g. "R0056", "CYTHON-001") hashes with
    FNV-1a — the system-wide string rule-ID mapping (T2-BRAIN-023). The old
    code raised ValueError on such IDs whenever the DLL was present.
    """
    if isinstance(rule_id, bool):
        return int(rule_id)
    if isinstance(rule_id, int):
        return rule_id & 0xFFFFFFFF
    if isinstance(rule_id, float):
        return int(rule_id) & 0xFFFFFFFF
    if isinstance(rule_id, str):
        try:
            return int(rule_id) & 0xFFFFFFFF
        except ValueError:
            pass
        digest = 0x811C9DC5
        for byte in rule_id.encode("utf-8"):
            digest ^= byte
            digest = (digest * 0x01000193) & 0xFFFFFFFF
        return digest
    return int(rule_id) & 0xFFFFFFFF


def push_event(event_type, source_ip, dest_ip, source_port, dest_port,
               protocol, tier_result, rule_id, severity, direction=0):
    if _f_push == NULL:
        return -1
    rule_id = _rule_to_u32(rule_id)
    cdef CEvent ev
    _fill_event(&ev, event_type, source_ip, dest_ip, source_port, dest_port,
                protocol, tier_result, rule_id, severity, direction)
    return (<fn_push_t>_f_push)(&ev)


def pop_event():
    if _f_pop == NULL:
        return None
    cdef CEvent ev
    if (<fn_pop_t>_f_pop)(&ev) != 0:
        return None
    out = BridgeEvent()
    out.event_type = ev.event_type
    out.source_ip = ev.source_ip
    out.dest_ip = ev.dest_ip
    out.source_port = ev.source_port
    out.dest_port = ev.dest_port
    out.protocol = ev.protocol
    out.direction = ev.direction
    out.layer_id = ev.layer_id
    out.tier_result = ev.tier_result
    out.payload_length = ev.payload_length
    out.rule_id = ev.rule_id
    out.severity = ev.severity
    out.reserved = ev.reserved
    out.timestamp = ev.timestamp
    out.source_pid = ev.source_pid
    out.defcon_impact = ev.defcon_impact
    out.event_id = ev.event_id
    out.schema_version = ev.schema_version
    out.confidence = ev.confidence
    out.provenance = ev.provenance
    out.parent_pid = ev.parent_pid
    out.evidence_offset = ev.evidence_offset
    out.evidence_length = ev.evidence_length
    return out


def get_event_count():
    if _f_events == NULL:
        return 0
    return (<fn_count_t>_f_events)()


def get_dropped_count():
    if _f_dropped == NULL:
        return 0
    return (<fn_count_t>_f_dropped)()


def get_defcon_level():
    if _f_defcon == NULL:
        return DEFCON_5_SAFE
    return (<fn_defcon_t>_f_defcon)()


def update_defcon(critical, blocked, kernel, total):
    if _f_update == NULL:
        return
    (<fn_update_defcon_t>_f_update)(critical, blocked, kernel, total)


cdef object _decode_label(void* fn, object fallback):
    if fn == NULL:
        return fallback
    cdef const char* raw = (<fn_label_t>fn)()
    if raw == NULL:
        return fallback
    return raw.decode("utf-8")


def get_defcon_label():
    return _decode_label(_f_label, DEFCON_LABELS.get(get_defcon_level(), "UNKNOWN"))


def get_defcon_description():
    return _decode_label(_f_desc, DEFCON_DESCRIPTIONS.get(get_defcon_level(), "Unknown DEFCON level"))


def block_ip(ip_string):
    if _f_block == NULL:
        return -1
    return (<fn_block_t>_f_block)(_ip_to_int(ip_string))


def unblock_ip(ip_string):
    if _f_unblock == NULL:
        return -1
    return (<fn_block_t>_f_unblock)(_ip_to_int(ip_string))


def push_tier2_match(rule_id, src_ip, dst_ip, src_port, dst_port, protocol, severity):
    return push_event(
        0,
        _ip_to_int(src_ip) if isinstance(src_ip, str) else src_ip,
        _ip_to_int(dst_ip) if isinstance(dst_ip, str) else dst_ip,
        src_port, dst_port, protocol, 2, rule_id, severity, 0,
    )


def ips_decide(rule_id, severity, src_ip, action="alert"):
    """Mirror of the shim helper: DEFCON-gated decision, fail-closed.

    block_ip() returning nonzero (including the C++ fail-closed -2) is an
    unavailable/rejected result, never a block. No host effect is claimed
    here; the decision string is advisory to the caller.
    """
    defcon = get_defcon_level()
    if defcon <= DEFCON_2_SEVERE and severity >= 2:
        if block_ip(src_ip) == 0:
            return "block"
        return "enforcement_unavailable"
    if severity >= 3:
        if block_ip(src_ip) == 0:
            return "block"
        return "enforcement_unavailable"
    if action == "block" and severity >= 2:
        if block_ip(src_ip) == 0:
            return "block"
        return "enforcement_unavailable"
    return action if action in ("alert", "block") else "alert"
