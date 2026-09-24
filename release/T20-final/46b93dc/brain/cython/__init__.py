"""cython_regex_scan — T5b Cython accelerator for the AEGIS Brain regex scan loop.

This package exposes two functions:
  - build_engine(rules_data) -> dict
  - scan_cython(payload, engine) -> tuple | None

If the Cython extension is compiled, calls dispatch to C-speed. Otherwise
the pure-Python fallback in `_py_fallback.py` is used.

Authority (T5b AC4):
  This module has NO path to policy, PEP, or Windows privilege. It is a pure
  string-search helper. It does not import subprocess, os.system, ctypes, or
  any firewall / WFP / Rust-PEP binding.
"""
from __future__ import annotations

# T5b: try the Cython-compiled extension first. On any failure (not
# compiled, ABI mismatch, missing build artifacts), fall back to pure Python
# in `_py_fallback.py`. The pure-Python path is the AC4 evidence: it works
# without any C extension and has no system authority.
try:
    from brain.cython.cython_regex_scan import (  # type: ignore
        build_engine as _cy_build_engine,
        scan_cython as _cy_scan_cython,
    )
    _CYTHON_AVAILABLE = True
except Exception:  # noqa: BLE001 (intentional broad catch for build/import errors)
    _CYTHON_AVAILABLE = False
    from . import _py_fallback as _fallback
    _cy_build_engine = _fallback.build_engine
    _cy_scan_cython = _fallback.scan_cython

build_engine = _cy_build_engine
scan_cython = _cy_scan_cython


def is_cython_available() -> bool:
    """True if the Cython extension is loaded; False if using pure Python."""
    return _CYTHON_AVAILABLE


__all__ = ["build_engine", "scan_cython", "is_cython_available"]
__version__ = "1.1.0"
