"""
aegis_brain_cython - AEGIS NIDS Brain Cython acceleration (Phase 17)

Provides native C implementations of hot-path functions:
  - fast_payload_scan(): C-level substring matching
  - fast_severity_lookup(): C-level dict lookup
  - fast_json_field_extract(): C-level JSON field parsing

Usage:
  from aegis_brain_cython.fast_scan import fast_payload_scan
  result = fast_payload_scan(payload_bytes, patterns_list)
"""

__version__ = "1.0.0"
