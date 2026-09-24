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

from libc.string cimport strlen, memcmp, memcpy
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

    The implementation intentionally uses Python bytes containment semantics
    rather than C `strstr()`.  `strstr()` requires NUL-terminated strings and
    truncates binary payloads at embedded NUL bytes, which would make the
    accelerated path disagree with the Python fallback.
    """
    cdef:
        Py_ssize_t i
        bytes pattern_bytes

    for i in range(len(patterns)):
        pattern_bytes = patterns[i]
        if pattern_bytes in payload:
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
        bytes field_bytes = field_name.encode('utf-8')
        bytes marker = b'"' + field_bytes + b'"'
        Py_ssize_t field_pos
        Py_ssize_t colon_pos
        Py_ssize_t value_start
        Py_ssize_t value_end

    # Use length-delimited bytes operations. This avoids C-string truncation,
    # unsafe pointers to temporary Python objects, and false matches inside a
    # different JSON field name.
    field_pos = json_bytes.find(marker)
    if field_pos < 0:
        return None

    colon_pos = json_bytes.find(b':', field_pos + len(marker))
    if colon_pos < 0:
        return None

    value_start = colon_pos + 1
    while value_start < len(json_bytes) and json_bytes[value_start] in b' \t\r\n':
        value_start += 1
    if value_start >= len(json_bytes) or json_bytes[value_start] != ord('"'):
        return None
    value_start += 1

    value_end = value_start
    while value_end < len(json_bytes):
        if json_bytes[value_end] == ord('"') and (value_end == value_start or json_bytes[value_end - 1] != ord('\\')):
            break
        value_end += 1
    if value_end >= len(json_bytes):
        return None
    return json_bytes[value_start:value_end].decode('utf-8', errors='replace')


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
