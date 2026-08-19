# cython: language_level=3
"""
Cython wrapper for aegis_shield.dll — faster than ctypes
Compiles to C, then to native .pyd — no GIL overhead for hot paths
"""

from cpython.ref cimport PyObject
from libc.stdint cimport int32_t, uint8_t, uint32_t

cdef extern from "aegis_shield.h" nogil:
    int32_t aegis_shield_init()
    int32_t aegis_shield_submit_packet(void *meta, const uint8_t *payload,
                                        uint32_t payload_len, void *result,
                                        uint32_t result_len)
    int32_t aegis_shield_get_forensic_hash(const uint8_t *data, uint32_t data_len,
                                             uint8_t *hash_out, uint32_t hash_len)
    void aegis_shield_shutdown()

# ── Python-facing API ──

def init() -> int:
    """Initialize the Rust shield engine. Returns 0 on success."""
    return aegis_shield_init()

def submit_packet(object meta_obj, bytes payload, object result_buf=None) -> int:
    """Submit a packet to the shield for forensic analysis.
    
    Args:
        meta_obj: AegisPktMeta-compatible object (ctypes struct)
        payload: raw packet bytes
        result_buf: optional output buffer
    
    Returns:
        0 on success, negative on error
    """
    cdef const uint8_t *payload_ptr = <const uint8_t *>payload
    cdef uint32_t payload_len = len(payload)
    cdef void *meta_ptr = NULL
    cdef void *result_ptr = NULL
    cdef uint32_t result_len = 0
    
    # If meta_obj is a ctypes struct, get its pointer
    if hasattr(meta_obj, '_as_parameter_'):
        meta_ptr = <void *><uintptr_t>meta_obj._as_parameter_.value
    
    if result_buf is not None:
        result_ptr = <void *><uintptr_t>result_buf
        result_len = len(result_buf)
    
    return aegis_shield_submit_packet(meta_ptr, payload_ptr, payload_len,
                                       result_ptr, result_len)

def get_forensic_hash(bytes data, bytes hash_out) -> int:
    """Compute forensic hash of data.
    
    Args:
        data: input data bytes
        hash_out: output buffer for hash (must be pre-allocated)
    
    Returns:
        0 on success
    """
    cdef const uint8_t *data_ptr = <const uint8_t *>data
    cdef uint32_t data_len = len(data)
    cdef uint8_t *hash_ptr = <uint8_t *>hash_out
    cdef uint32_t hash_len = len(hash_out)
    
    return aegis_shield_get_forensic_hash(data_ptr, data_len, hash_ptr, hash_len)

def shutdown():
    """Shutdown the shield engine."""
    aegis_shield_shutdown()
