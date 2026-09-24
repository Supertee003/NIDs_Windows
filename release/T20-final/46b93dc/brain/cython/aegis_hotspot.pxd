# aegis_hotspot.pxd — Cython declarations for AEGIS NIDS C-level hotspots
#
# This .pxd file provides C-level type declarations and extern function
# bindings for the AEGIS NIDS performance-critical paths.
#
# Hotspot targets:
#   1. 5-tuple extraction from binary packets (struct.unpack)
#   2. SHA-256 forensic hash chain (hashlib.sha256)
#   3. Byte-level pattern scanning (NOP sled, shellcode markers)
#   4. Packet sanity validation (type/range checks)

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t
from libc.string cimport memcpy, memcmp

# C-level AegisIpcEvent structure (52 bytes, pack(1))
# Matches C++ IpcEvent, Zig AegisIpcEvent, Python AegisIpcEvent ctypes
cdef packed struct C_AegisIpcEvent:
    uint32_t event_type
    uint32_t source_ip
    uint32_t dest_ip
    uint16_t source_port
    uint16_t dest_port
    uint8_t  protocol
    uint8_t  direction
    uint8_t  layer_id
    uint8_t  tier_result
    uint32_t payload_length
    uint32_t rule_id
    uint32_t severity
    uint32_t reserved
    uint64_t timestamp
    uint32_t source_pid
    uint32_t defcon_impact

# C-level AegisFileEvent structure (36 bytes, pack(1))
# Matches Zig AegisFileEvent in minifilter_reader.zig
cdef packed struct C_AegisFileEvent:
    uint32_t event_type
    uint32_t operation
    uint32_t file_name_len
    uint32_t process_id
    uint32_t rule_id
    uint32_t severity
    uint32_t reserved
    uint64_t timestamp
