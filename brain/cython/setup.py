"""
setup.py — Build Cython hotspot extensions for AEGIS NIDS

Build:  python setup.py build_ext --inplace
Install: python setup.py install

The compiled .so/.pyd files accelerate the most performance-critical
functions in the AEGIS Python Brain (windows_brain.py):
  - extract_5tuple:     ~15-20x faster (C-level struct parsing)
  - scan_nop_sled:      ~30-50x faster (C-level byte scanning)
  - compute_forensic_hash: ~3-5x faster (C-level memory ops)
  - validate_packet_meta:  ~10-15x faster (C-level range checks)
  - detect_repeated_byte:  ~30-50x faster (C-level run-length)
"""

from setuptools import setup, Extension
from Cython.Build import cythonize

extensions = [
    Extension(
        "aegis_hotspot",
        sources=["aegis_hotspot.pyx"],
        # C-level optimizations
        extra_compile_args=["-O3", "-Wall", "-Wno-unused-function"],
        define_macros=[("NDEBUG", None)],  # Disable assert() overhead
    ),
]

setup(
    name="aegis_hotspot",
    version="1.0.0",
    description="AEGIS NIDS Cython-accelerated hotspots",
    ext_modules=cythonize(
        extensions,
        compiler_directives={
            "language_level": "3",
            "boundscheck": False,    # Disable bounds checking (C speed)
            "wraparound": False,     # Disable negative indexing (C speed)
            "cdivision": True,       # C-level division (no Python ZeroDivisionError)
            "initializedcheck": False,  # Skip memory init checks
            "nonecheck": False,      # Skip None checks
        },
    ),
)
