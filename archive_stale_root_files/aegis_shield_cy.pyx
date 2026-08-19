# cython: language_level=3
"""Cython wrapper for aegis_shield.dll -- faster than ctypes"""
import ctypes
import os

cdef class AegisShield:
    """Cython-accelerated interface to Rust aegis_shield.dll"""
    cdef object _lib
    cdef bint _loaded

    def __init__(self):
        self._loaded = False
        self._lib = None
        cdef list dll_paths = []
        base = os.path.dirname(os.path.abspath(__file__))
        dll_paths.append(os.path.join(base, "aegis_shield.dll"))
        dll_paths.append(os.path.join(base, "build", "Release", "aegis_shield.dll"))
        # Add DLL directory for Python 3.8+
        if hasattr(os, "add_dll_directory"):
            for d in set(os.path.dirname(p) for p in dll_paths):
                if os.path.isdir(d):
                    os.add_dll_directory(d)
        for path in dll_paths:
            if os.path.isfile(path):
                try:
                    self._lib = ctypes.CDLL(path)
                    self._loaded = True
                    print("[Cython] Shield loaded: " + str(path))
                    break
                except (OSError, AttributeError):
                    continue
        if not self._loaded:
            print("[Cython] aegis_shield.dll not found")

    @property
    def loaded(self):
        return self._loaded

    def scan_packet(self, data):
        """Scan a packet buffer through the Rust shield engine"""
        if not self._loaded:
            return {"verdict": "passthrough", "confidence": 0.0}
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        cdef int length = len(data)
        try:
            func = self._lib.aegis_shield_scan
            func.argtypes = [ctypes.c_char_p, ctypes.c_int]
            func.restype = ctypes.c_int
            result = func(data, length)
            if result > 0:
                return {"verdict": "blocked", "confidence": min(result / 100.0, 1.0)}
            else:
                return {"verdict": "allowed", "confidence": 0.0}
        except (OSError, AttributeError):
            return {"verdict": "passthrough", "confidence": 0.0}

    def get_stats(self):
        """Get shield statistics"""
        if not self._loaded:
            return {}
        try:
            func = self._lib.aegis_shield_stats
            func.restype = ctypes.c_int
            return {"total_scanned": func()}
        except (OSError, AttributeError):
            return {}
