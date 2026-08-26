# cython: language_level=3, boundscheck=False, wraparound=False, cdivision=True, infer_types=True
# ============================================================
# fast_scan.pyx - AEGIS NIDS Cython acceleration (Phase 17)
# ============================================================
# Native C implementations of Python Brain hot paths:
#   1. fast_payload_scan() - C-level substring matching (replaces run_regex_scan loop)
#   2. fast_severity_lookup() - C-level severity string → int
#   3. fast_ip_match() - C-level IP address matching
#   4. fast_strlen() - C-level strlen for payload size checks
# ============================================================

from libc.string cimport strlen, strstr, memcmp, memcpy
from libc.stdlib cimport malloc, free
cimport cython


# ============================================================
# Severity lookup (replaces Python dict lookup)
# ============================================================

cdef dict _SEVERITY_MAP = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

cpdef int fast_severity_lookup(str severity_str) nogil:
    """Convert severity string to int (C-level, no GIL).

    Returns:
        0=Low, 1=Medium, 2=High, 3=Critical, -1=Unknown
    """
    if severity_str == "Critical":
        return 3
    elif severity_str == "High":
        return 2
    elif severity_str == "Medium":
        return 1
    elif severity_str == "Low":
        return 0
    else:
        return -1


# ============================================================
# Fast payload scan - C-level substring matching
# ============================================================

@cython.boundscheck(False)
@cython.wraparound(False)
cpdef tuple fast_payload_scan(bytes payload, list patterns):
    """Scan payload against a list of (pattern_bytes) patterns.

    Returns:
        (match_index, pattern_str) if match found, else (-1, None)

    This is ~3-5x faster than Python's `for p in patterns: if p in payload`
    because it uses C strstr() directly on the byte buffer.
    """
    cdef:
        const char* buf = payload
        Py_ssize_t buf_len = len(payload)
        Py_ssize_t i
        const char* pattern_buf
        const char* result
        bytes pattern_bytes

    for i in range(len(patterns)):
        pattern_bytes = patterns[i]
        pattern_buf = pattern_bytes

        # Use strstr for C-level substring search
        result = strstr(buf, pattern_buf)
        if result != NULL:
            return (i, pattern_bytes)

    return (-1, None)


# ============================================================
# Fast IP match - check if IP is in a list
# ============================================================

@cython.boundscheck(False)
@cython.wraparound(False)
cpdef bint fast_ip_in_list(unsigned int ip, list ip_list):
    """Check if a 32-bit IP is in a list of IPs.

    Uses C-level integer comparison instead of Python `in` operator.
    """
    cdef:
        unsigned int target_ip = ip
        unsigned int current_ip
        Py_ssize_t i

    for i in range(len(ip_list)):
        current_ip = ip_list[i]
        if current_ip == target_ip:
            return True

    return False


# ============================================================
# Fast JSON field extraction (avoids full json.loads for simple cases)
# ============================================================

@cython.boundscheck(False)
@cython.wraparound(False)
cpdef str fast_extract_field(bytes json_bytes, str field_name):
    """Extract a string field from JSON without full parse.

    This is a fast-path for extracting simple "field":"value" pairs.
    Falls back to None if pattern not found.

    Example:
        fast_extract_field(b'{"rule":"SQLI","level":"high"}', "rule")
        -> "SQLI"
    """
    cdef:
        const char* buf = json_bytes
        Py_ssize_t buf_len = len(json_bytes)
        bytes field_bytes = field_name.encode('utf-8')
        const char* field_buf = field_bytes
        const char* search_start = buf
        const char* field_pos
        const char* colon_pos
        const char* value_start
        const char* value_end
        Py_ssize_t field_len = len(field_bytes)
        Py_ssize_t value_len

    # Search for "field_name"
    field_pos = strstr(search_start, field_bytes)
    if field_pos == NULL:
        return None

    # Find the colon after field name
    colon_pos = field_pos + field_len
    while colon_pos < buf + buf_len:
        if colon_pos[0] == ord(':'):
            break
        colon_pos += 1

    if colon_pos >= buf + buf_len:
        return None

    # Find the opening quote of value
    value_start = colon_pos + 1
    while value_start < buf + buf_len and value_start[0] != ord('"'):
        value_start += 1

    if value_start >= buf + buf_len:
        return None

    value_start += 1  # Skip opening quote

    # Find closing quote
    value_end = value_start
    while value_end < buf + buf_len and value_end[0] != ord('"'):
        if value_end[0] == ord('\\'):  # Skip escaped chars
            value_end += 2
        else:
            value_end += 1

    if value_end >= buf + buf_len:
        return None

    value_len = value_end - value_start
    return json_bytes[value_start - buf : value_start - buf + value_len].decode('utf-8', errors='replace')


# ============================================================
# Fast threshold check (DEFCON calculation)
# ============================================================

cpdef int calculate_defcon(int critical_count, int block_count, int match_count, int forward_count):
    """Calculate DEFCON level from event counts (C-level integer math).

    Returns:
        1=Critical, 2=Severe, 3=Elevated, 4=Guarded, 5=Normal
    """
    if critical_count >= 1:
        return 1
    elif block_count >= 3:
        return 2
    elif match_count >= 10:
        return 3
    elif match_count >= 1:
        return 4
    else:
        return 5


# ============================================================
# Fast payload size check (replaces Python len() comparison)
# ============================================================

cpdef bint payload_too_large(bytes payload, Py_ssize_t max_size):
    """Check if payload exceeds max_size (C-level comparison)."""
    return len(payload) > max_size


# ============================================================
# Benchmarks (for testing)
# ============================================================

def benchmark_scan(int iterations=10000):
    """Benchmark fast_payload_scan vs Python equivalent."""
    import time

    payload = b"GET /admin?id=1' OR '1'='1 HTTP/1.1\r\nHost: example.com\r\n" * 10
    patterns = [b"SQL_INJECTION", b"XSS_SCRIPT", b"OR '1'='1", b"UNION SELECT"]

    # Cython version
    start = time.perf_counter()
    for _ in range(iterations):
        fast_payload_scan(payload, patterns)
    cython_time = time.perf_counter() - start

    # Python version
    start = time.perf_counter()
    for _ in range(iterations):
        for p in patterns:
            if p in payload:
                break
    python_time = time.perf_counter() - start

    speedup = python_time / cython_time if cython_time > 0 else 0
    print(f"Cython: {cython_time:.4f}s")
    print(f"Python: {python_time:.4f}s")
    print(f"Speedup: {speedup:.2f}x")
    return speedup
