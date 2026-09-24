"""
setup.py — Build Cython hotspot extensions for AEGIS NIDS

Build:  python setup.py build_ext --inplace
Install: python setup.py install

The compiled .so/.pyd files accelerate the most performance-critical
functions in the AEGIS Python Brain (windows_brain.py):
  - aegis_hotspot.scan_nop_sled:      ~30-50x faster (C-level byte scanning)
  - aegis_hotspot.detect_repeated_byte: ~30-50x faster (C-level run-length)
  - aegis_hotspot.scan_shellcode_markers: ~20-30x faster (C-level byte scanning)
  - aegis_hotspot.extract_5tuple:     ~15-20x faster (C-level struct parsing)
  - cython_regex_scan.scan_cython:    ~2-3x faster (C-level loop over re.Pattern)
"""

from setuptools import setup, Extension
from Cython.Build import cythonize

extensions = [
    Extension(
        "aegis_hotspot",
        sources=["aegis_hotspot.pyx"],
        # C-level optimizations
        extra_compile_args=["-O3", "-Wall"],
        define_macros=[("NDEBUG", None)],  # Disable assert() overhead
    ),
    Extension(
        "cython_regex_scan",
        sources=["cython_regex_scan.pyx"],
        extra_compile_args=["-O3", "-Wall"],
        define_macros=[("NDEBUG", None)],
    ),
]

setup(
    name="aegis_cython",
    version="1.1.0",
    description="AEGIS NIDS Cython-accelerated hotspots (T5b)",
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
