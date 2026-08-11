"""
aegis_wfp_ioctl.py — Python ↔ WFP Kernel Driver IOCTL Bridge

Provides DeviceIoControl access to the WFP driver for Semi-NIDS control:
  - Block/Unblock IP at kernel level
  - Update detection thresholds
  - Set fail-open mode
  - Read Semi-NIDS kernel state

This is the low-level bridge that the console and Vaadin UI use
to enforce decisions at the kernel packet filter level.

Layer 4: Python → Layer 1: Kernel (via IOCTL)
"""

import ctypes
import logging
import struct
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aegis.wfp.ioctl")

# ─── IOCTL Codes (must match aegis_wfp.c) ───
IOCTL_AEGIS_GET_RING_ADDR       = 0x800
IOCTL_AEGIS_GET_STATS           = 0x801
IOCTL_AEGIS_SEMI_BLOCK_IP       = 0x802
IOCTL_AEGIS_SEMI_UNBLOCK_IP     = 0x803
IOCTL_AEGIS_SEMI_SET_THRESHOLDS = 0x804
IOCTL_AEGIS_SEMI_GET_STATE      = 0x805
IOCTL_AEGIS_SEMI_SET_FAILOPEN   = 0x806
IOCTL_AEGIS_SEMI_WHITELIST_IP   = 0x807

# ─── Windows API ───
kernel32 = ctypes.windll.kernel32

GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# ─── C Structures (matching kernel) ───

class SEMI_NIDS_THRESHOLDS_C(ctypes.Structure):
    """Must match SEMI_NIDS_THRESHOLDS in aegis_wfp.c"""
    _pack_ = 1
    _fields_ = [
        ("block_threshold",      ctypes.c_int32),
        ("ratelimit_threshold",  ctypes.c_int32),
        ("alert_threshold",      ctypes.c_int32),
    ]

class AEGIS_RING_HEADER_C(ctypes.Structure):
    """Must match AEGIS_RING_HEADER in aegis_wfp.c"""
    _pack_ = 1
    _fields_ = [
        ("write_pos",     ctypes.c_uint32),
        ("read_pos",      ctypes.c_uint32),
        ("capacity",      ctypes.c_uint32),
        ("packet_count",  ctypes.c_uint32),
        ("dropped_count", ctypes.c_uint32),
    ]


# ─── WFP IOCTL Bridge ───

class WfpIoctlBridge:
    """Manages the device handle for WFP driver IOCTL communication.

    On Windows, opens \\\\.\\AegisWfp device handle.
    On Linux/CI, stubs are used for testing.
    """

    DEVICE_PATH = r"\\.\AegisWfp"

    def __init__(self):
        self._handle = None
        self._is_windows = hasattr(ctypes, 'windll')

    def open(self) -> bool:
        """Open the WFP driver device handle."""
        if not self._is_windows:
            logger.infoF("WFP IOCTL: Not on Windows — using stub mode")
            return True

        self._handle = kernel32.CreateFileW(
            self.DEVICE_PATH,
            GENERIC_READ | GENERIC_WRITE,
            0,  # No sharing
            None,  # Default security
            OPEN_EXISTING,
            0,  # Normal attributes
            None  # No template
        )

        if self._handle == INVALID_HANDLE_VALUE:
            logger.error("WFP IOCTL: Failed to open device %s (error=%d)",
                        self.DEVICE_PATH, kernel32.GetLastError())
            return False

        logger.info("WFP IOCTL: Device opened successfully")
        return True

    def close(self) -> None:
        """Close the device handle."""
        if self._handle and self._handle != INVALID_HANDLE_VALUE:
            kernel32.CloseHandle(self._handle)
            self._handle = None

    def _ioctl(self, ioctl_code: int, in_buf=None, in_size: int = 0,
               out_buf=None, out_size: int = 0) -> int:
        """Execute DeviceIoControl. Returns bytes returned, or -1 on error."""
        if not self._is_windows or. self._handle is None:
            return -1  # Stub mode

        bytes_returned = ctypes.c_uint32(0)

        success = kernel32.DeviceIoControl(
            self._handle,
            ioctl_code,
            in_buf, in_size,
            out_buf, out_size,
            ctypes.byref(bytes_returned),
            None  # No overlapped
        )

        if not success:
            logger.error("WFP IOCTL 0x%x failed: error=%d",
                        ioctl_code, kernel32.GetLastError())
            return -1

        return bytes_returned.value

    # ─── Semi-NIDS IOCTL Methods ───

    def block_ip(self, ip: int) -> bool:
        """Block an IP at kernel level (IOCTL 0x802).

        Args:
            ip: IPv4 address as 32-bit integer (network byte order)

        Returns:
            True if IOCTL succeeded
        """
        in_buf = ctypes.c_uint32(ip)
        rc = self._ioctl(IOCTL_AEGIS_SEMI_BLOCK_IP,
                        ctypes.byref(in_buf), ctypes.sizeof(in_buf))
        if rc >= 0:
            logger.info("WFP IOCTL: Blocked IP 0x%08x", ip)
        return rc >= 0

    def unblock_ip(self, ip: int) -> bool:
        """Unblock IP + add to whitelist (IOCTL 0x803).

        Args:
            ip: IPv4 address as 32-bit integer

        Returns:
            True if IOCTL succeeded
        """
        in_buf = ctypes.c_uint32(ip)
        rc = self._ioctl(IOCTL_AEGIS_SEMI_UNBLOCK_IP,
                        ctypes.byref(in_buf), ctypes.sizeof(in_buf))
        if rc >= 0:
            logger.info("WFP IOCTL: Unblocked + whitelisted IP 0x%08x", ip)
        return rc >= 0

    def whitelist_ip(self, ip: int) -> bool:
        """Add IP to whitelist only (IOCTL 0x807). Doesn't remove from blocks.

        Args:
            ip: IPv4 address as 32-bit integer

        Returns:
            True if IOCTL succeeded
        """
        in_buf = ctypes.c_uint32(ip)
        rc = self._ioctl(IOCTL_AEGIS_SEMI_WHITELIST_IP,
                        ctypes.byref(in_buf), ctypes.sizeof(in_buf))
        if rc >= 0:
            logger.info("WFP IOCTL: Whitelisted IP 0x%08x", ip)
        return rc >= 0

    def set_thresholds(self, block: int, ratelimit: int, alert: int) -> bool:
        """Update Semi-NIDS detection thresholds (IOCTL 0x804).

        Args:
            block: Score >= this + High confidence = Block (default 60)
            ratelimit: Score >= this + Med confidence = Rate Limit (default 40)
            alert: Score >= this = Alert only (default 20)

        Returns:
            True if IOCTL succeeded
        """
        t = SEMI_NIDS_THRESHOLDS_C()
        t.block_threshold = block
        t.ratelimit_threshold = ratelimit
        t.alert_threshold = alert
        rc = self._ioctl(IOCTL_AEGIS_SEMI_SET_THRESHOLDS,
                        ctypes.byref(t), ctypes.sizeof(t))
        if rc >= 0:
            logger.info("WFP IOCTL: Thresholds set: block=%d, rl=%d, alert=%d",
                       block, ratelimit, alert)
        return rc >= 0

    def set_fail_open(self, active: bool) -> bool:
        """Force fail-open mode on/off (IOCTL 0x806).

        Args:
            active: True = activate fail-open, False = deactivate

        Returns:
            True if IOCTL succeeded
        """
        in_buf = ctypes.c_bool(active)
        rc = self._ioctl(IOCTL_AEGIS_SEMI_SET_FAILOPEN,
                        ctypes.byref(in_buf), ctypes.sizeof(in_buf))
        if rc >= 0:
            logger.info("WFP IOCTL: Fail-open %s", "ACTIVATED" if active else "DEACTIVATED")
        return rc >= 0

    def get_ring_stats(self) -> Optional[dict]:
        """Get WFP ring buffer statistics (IOCTL 0x801).

        Returns:
            Dict with write_pos, read_pos, capacity, packet_count, dropped_count
        """
        out = AEGIS_RING_HEADER_C()
        rc = self._ioctl(IOCTL_AEGIS_GET_STATS,
                        out_size=ctypes.sizeof(out),
                        out_buf=ctypes.byref(out))
        if rc >= 0:
            return {
                "write_pos": out.write_pos,
                "read_pos": out.read_pos,
                "capacity": out.capacity,
                "packet_count": out.packet_count,
                "dropped_count": out.dropped_count,
            }
        return None

    # ─── IP Utilities ───

    @staticmethod
    def ip_to_int(ip_str: str) -> int:
        """Convert '192.168.1.1' → 0xC0A80101 (network byte order)."""
        parts = ip_str.split('.')
        if len(parts) != 4:
            return 0
        return (int(parts[0]) << 24) | (int(parts[1]) << 16) | \
               (int(parts[2]) << 8) | int(parts[3])

    @staticmethod
    def int_to_ip(ip: int) -> str:
        """Convert 0xC0A80101 → '192.168.1.1'."""
        return f"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}"


# ─── Singleton ───
_wfp_bridge: Optional[WfpIoctlBridge] = None

def get_wfp_bridge() -> WfpIoctlBridge:
    """Get or create the global WFP IOCTL bridge instance."""
    global _wfp_bridge
    if _wfp_bridge is None:
        _wfp_bridge = WfpIoctlBridge()
        _wfp_bridge.open()
    return _wfp_bridge
