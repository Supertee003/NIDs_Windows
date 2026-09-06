"""
aegis_bridge_ctypes.py — Python ctypes Bindings for C++ IPC Bridge

Python Brain (Tier-2) uses ctypes to call the C++ IPC Bridge DLL.
This enables Python to:
  - Push regex inspection results (Tier-2 matches) to the Bridge
  - Receive events from Zig Core (Tier-1) for deep inspection
  - Request IPS blocking of malicious IPs
  - Get DEFCON level for IPS policy decisions

Architecture: Python Brain → C++ Bridge (via ctypes) → Dashboard
Build: The aegis_ipc.dll must be built and placed in the project directory
"""

import ctypes
import os
import struct
import platform

# ====== Load C++ IPC Bridge Shared Library ======
# Platform: Windows = .dll, Linux = .so, macOS = .dylib
_is_windows = platform.system() == "Windows"
_lib_name = "aegis_ipc.dll" if _is_windows else "libaegis_ipc.so"

# Search in multiple locations (ordered by likelihood)
_base_dir = os.path.dirname(os.path.abspath(__file__))
_dll_paths = [
    os.path.join(_base_dir, _lib_name),                          # bridge/
    os.path.join(_base_dir, "..", "bridge", _lib_name),          # ./bridge/
    os.path.join(_base_dir, "..", "build", "Release", _lib_name),  # build/Release/ (MSVC)
    os.path.join(_base_dir, "..", "build", "Debug", _lib_name),    # build/Debug/ (MSVC)
    os.path.join(_base_dir, "..", "build", _lib_name),           # build/ (MinGW/single-config)
    os.path.join(_base_dir, "build", _lib_name),                 # alternate
    os.path.join(_base_dir, "..", "target", "release", _lib_name),  # target/release/ (Rust-like)
]

_bridge_dll = None
for path in _dll_paths:
    abs_path = os.path.abspath(path)
    if os.path.exists(abs_path):
        _bridge_dll = ctypes.CDLL(abs_path)
        break

if _bridge_dll is None:
    # Try system path as last resort
    try:
        _bridge_dll = ctypes.CDLL(_lib_name)
    except OSError:
        print("[AEGIS Bridge] Warning: aegis_ipc.dll not found — running in standalone mode")
        _bridge_dll = None


# ====== IPC Event Structure (48 bytes — matches C++ IpcEvent) ======
class AegisIpcEvent(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        # ===== Core fields (bytes 0-39 — kernel AEGIS_EVENT_HEADER compatible) =====
        ("event_type",      ctypes.c_uint32),   # 0=NETWORK, 1=KERNEL_FILE, 2=KERNEL_PROCESS, 3=L2_PIPE
        ("source_ip",       ctypes.c_uint32),   # IPv4 source (0 for host-only events)
        ("dest_ip",         ctypes.c_uint32),   # IPv4 destination (0 for host-only events)
        ("source_port",     ctypes.c_uint16),   # Source port (0 for host-only)
        ("dest_port",       ctypes.c_uint16),   # Destination port (0 for host-only)
        ("protocol",        ctypes.c_uint8),    # 6=TCP, 17=UDP, 1=ICMP (0 for host-only)
        ("direction",       ctypes.c_uint8),    # 0=inbound, 1=outbound
        ("layer_id",        ctypes.c_uint8),    # Layer where event originated
        ("tier_result",     ctypes.c_uint8),    # 0=NoMatch, 1=Tier1, 2=Tier2, 3=Tier3
        ("payload_length",  ctypes.c_uint32),   # Payload length
        ("rule_id",         ctypes.c_uint32),   # Matched rule ID (0 if none)
        ("severity",        ctypes.c_uint32),   # 0=Low, 1=Medium, 2=High, 3=Critical
        ("reserved",        ctypes.c_uint32),   # Reserved (0)
        ("timestamp",       ctypes.c_uint64),   # Event timestamp (ms since epoch)
        # ===== Extended fields (bytes 40-47 — backward compatible) =====
        ("source_pid",      ctypes.c_uint32),   # PID of source process (0 if unknown)
        ("defcon_impact",   ctypes.c_uint32),   # DEFCON impact level (1-5)
        # ===== G2 canonical extension (bytes 48-71 — NEW) =====
        ("event_id",        ctypes.c_uint64),   # Unique event ID
        ("schema_version",  ctypes.c_uint16),   # Schema version (currently 2)
        ("confidence",      ctypes.c_uint8),    # Detection confidence 0-100
        ("provenance",      ctypes.c_uint8),    # SubsystemId that produced this
        ("parent_pid",      ctypes.c_uint32),   # Parent process PID (0 if unknown)
        ("evidence_offset", ctypes.c_uint32),   # Offset to evidence in payload
        ("evidence_length", ctypes.c_uint32),   # Length of evidence data
    ]


# ====== IPC Command Structure ======
class AegisIpcCommand(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("command_id",        ctypes.c_uint32),
        ("target_subsystem",  ctypes.c_uint32),
        ("payload_size",      ctypes.c_uint32),
        ("response_expected", ctypes.c_uint32),
        ("timestamp",         ctypes.c_uint64),
    ]


# ====== DEFCON Levels ======
DEFCON_1_MAXIMUM  = 1   # 10+ critical OR 5+ blocks OR kernel threats
DEFCON_2_SEVERE   = 2   # 5+ critical OR 3+ blocks
DEFCON_3_HIGH     = 3   # 5+ alerts OR 1+ critical
DEFCON_4_ELEVATED = 4   # 1-5 alerts
DEFCON_5_SAFE     = 5   # 0 alerts

DEFCON_LABELS = {
    1: "MAXIMUM",
    2: "SEVERE",
    3: "HIGH",
    4: "ELEVATED",
    5: "SAFE",
}

DEFCON_DESCRIPTIONS = {
    1: "10+ critical alerts OR 5+ blocked IPs OR kernel-level threats detected",
    2: "5+ critical alerts OR 3+ blocked IPs — active threat campaign",
    3: "5+ alerts OR 1+ critical — significant threat activity",
    4: "1-5 alerts — low-level threat activity observed",
    5: "No alerts — all systems nominal",
}


# ====== Bridge Function Wrappers ======
def _get_func(name, arg_types=None, restype=ctypes.c_int32):
    """Get a function from the DLL with type annotations."""
    if _bridge_dll is None:
        return None
    func = getattr(_bridge_dll, name, None)
    if func is None:
        return None
    if arg_types:
        func.argtypes = arg_types
    func.restype = restype
    return func


# ====== Initialization ======
_bridge_init = _get_func("aegis_bridge_init", restype=ctypes.c_int32)
_bridge_shutdown = _get_func("aegis_bridge_shutdown", restype=ctypes.c_int32)


def bridge_init():
    """Initialize the C++ IPC Bridge. Returns 0 on success."""
    if _bridge_init:
        return _bridge_init()
    return -1


def bridge_shutdown():
    """Shutdown the C++ IPC Bridge. Returns 0 on success."""
    if _bridge_shutdown:
        return _bridge_shutdown()
    return -1


# ====== Event Passing ======
_bridge_push = _get_func("aegis_bridge_push_event",
    [ctypes.POINTER(AegisIpcEvent)], ctypes.c_int32)
_bridge_pop = _get_func("aegis_bridge_pop_event",
    [ctypes.POINTER(AegisIpcEvent)], ctypes.c_int32)


def push_event(event_type, source_ip, dest_ip, source_port, dest_port,
               protocol, tier_result, rule_id, severity, direction=0):
    """Push an event to the C++ Bridge event queue."""
    if _bridge_push is None:
        return -1

    event = AegisIpcEvent()
    event.event_type     = event_type
    event.source_ip      = source_ip
    event.dest_ip        = dest_ip
    event.source_port    = source_port
    event.dest_port      = dest_port
    event.protocol       = protocol
    event.direction      = direction
    event.layer_id       = 0 if event_type == 0 else event_type
    event.tier_result    = tier_result   # 2 = Tier-2 regex match
    event.payload_length = 0
    event.rule_id        = int(rule_id) if isinstance(rule_id, (str, float)) else rule_id
    event.severity       = severity
    event.reserved       = 0
    event.timestamp      = 0
    event.source_pid     = 0
    event.defcon_impact  = severity if severity >= 3 else 4

    return _bridge_push(ctypes.byref(event))


def pop_event():
    """Pop an event from the C++ Bridge event queue. Returns AegisIpcEvent or None."""
    if _bridge_pop is None:
        return None

    event = AegisIpcEvent()
    result = _bridge_pop(ctypes.byref(event))
    if result == 0:
        return event
    return None


# ====== DEFCON ======
_bridge_get_defcon = _get_func("aegis_bridge_get_defcon", restype=ctypes.c_uint8)
_bridge_update_defcon = _get_func("aegis_bridge_update_defcon",
    [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32], None)
_bridge_get_defcon_label = _get_func("aegis_bridge_get_defcon_label",
    restype=ctypes.c_char_p)
_bridge_get_defcon_desc = _get_func("aegis_bridge_get_defcon_description",
    restype=ctypes.c_char_p)


def get_defcon_level():
    """Get current DEFCON level (1-5)."""
    if _bridge_get_defcon:
        return _bridge_get_defcon()
    return DEFCON_5_SAFE


def update_defcon(critical, blocked, kernel, total):
    """Update DEFCON counters from subsystems."""
    if _bridge_update_defcon:
        _bridge_update_defcon(critical, blocked, kernel, total)


def get_defcon_label():
    """Get DEFCON level label string."""
    if _bridge_get_defcon_label:
        result = _bridge_get_defcon_label()
        if result is not None:
            return result.decode('utf-8')
        # NULL return from C function - use fallback
    level = get_defcon_level()
    return DEFCON_LABELS.get(level, "UNKNOWN")


def get_defcon_description():
    """Get DEFCON level description string."""
    if _bridge_get_defcon_desc:
        result = _bridge_get_defcon_desc()
        if result is not None:
            return result.decode('utf-8')
        # NULL return from C function - use fallback
    level = get_defcon_level()
    return DEFCON_DESCRIPTIONS.get(level, "Unknown DEFCON level")


# ====== IPS ======
_bridge_block_ip = _get_func("aegis_bridge_block_ip",
    [ctypes.c_uint32], ctypes.c_int32)
_bridge_unblock_ip = _get_func("aegis_bridge_unblock_ip",
    [ctypes.c_uint32], ctypes.c_int32)


def block_ip(ip_string):
    """Block an IP address via WFP callout (IPS enforcement)."""
    if _bridge_block_ip is None:
        return -1
    ip_int = _ip_to_int(ip_string)
    return _bridge_block_ip(ip_int)


def unblock_ip(ip_string):
    """Unblock a previously blocked IP address."""
    if _bridge_unblock_ip is None:
        return -1
    ip_int = _ip_to_int(ip_string)
    return _bridge_unblock_ip(ip_int)


def _ip_to_int(ip_string):
    """Convert IP string (e.g., '192.168.1.1') to uint32."""
    try:
        parts = ip_string.split('.')
        if len(parts) != 4:
            return 0
        return struct.unpack('>I', struct.pack('BBBB',
            int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])))[0]
    except (ValueError, IndexError):
        return 0


def _int_to_ip(ip_int):
    """Convert uint32 to IP string."""
    return '.'.join(str((ip_int >> i) & 0xFF) for i in (0, 8, 16, 24))


# ====== Statistics ======
_bridge_get_event_count = _get_func("aegis_bridge_get_event_count",
    restype=ctypes.c_uint32)
_bridge_get_dropped = _get_func("aegis_bridge_get_dropped_count",
    restype=ctypes.c_uint32)


def get_event_count():
    """Get number of events currently in the queue."""
    if _bridge_get_event_count:
        return _bridge_get_event_count()
    return 0


def get_dropped_count():
    """Get number of events dropped due to queue overflow."""
    if _bridge_get_dropped:
        return _bridge_get_dropped()
    return 0


# ====== Tier-2 Helper: Push regex inspection result ======
def push_tier2_match(rule_id, src_ip, dst_ip, src_port, dst_port, protocol, severity):
    """Push a Tier-2 (Python Brain) regex match result to the Bridge."""
    return push_event(
        event_type=0,          # NETWORK
        source_ip=_ip_to_int(src_ip) if isinstance(src_ip, str) else src_ip,
        dest_ip=_ip_to_int(dst_ip) if isinstance(dst_ip, str) else dst_ip,
        source_port=src_port,
        dest_port=dst_port,
        protocol=protocol,
        tier_result=2,         # Tier-2 regex match
        rule_id=rule_id,
        severity=severity,
        direction=0,
    )


# ====== Tier-2 Helper: IPS Decision ======
def ips_decide(rule_id, severity, src_ip, action="alert"):
    """
    Make an IPS decision based on rule severity and DEFCON level.

    Args:
        rule_id: Matched rule ID (e.g., 'R0056')
        severity: Rule severity (0-3)
        src_ip: Source IP address
        action: Default action from rule ('alert' or 'block')

    Returns:
        Decision string: 'allow', 'alert', or 'block'
    """
    defcon = get_defcon_level()

    # DEFCON 1-2: Block all threats automatically
    if defcon <= DEFCON_2_SEVERE and severity >= 2:
        block_ip(src_ip)
        return "block"

    # DEFCON 3-4: Block critical, alert others
    if severity >= 3:
        block_ip(src_ip)
        return "block"

    # DEFCON 5: Follow rule's default action
    if action == "block" and severity >= 2:
        block_ip(src_ip)
        return "block"

    return action if action in ("alert", "block") else "alert"
