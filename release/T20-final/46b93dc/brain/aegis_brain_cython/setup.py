# ============================================================
# AEGIS NIDS Brain - Cython Acceleration Module (Phase 17)
# ============================================================
# Compiles hot-path functions from windows_brain.py into native C
# for ~30-50% speedup on event processing.
#
# Build:   python setup.py build_ext --inplace
# Install: pip install -e .
# ============================================================

import os
from setuptools import setup, Extension
from Cython.Build import cythonize

# Get directory of this setup.py (handles running from any CWD)
HERE = os.path.dirname(os.path.abspath(__file__))

extensions = [
    Extension(
        "aegis_brain_cython.fast_scan",
        [os.path.join(HERE, "fast_scan.pyx")],
        extra_compile_args=["-O2"],
    ),
]

setup(
    name="aegis_brain_cython",
    version="1.0.0",
    description="AEGIS NIDS Brain Cython acceleration module",
    package_dir={"aegis_brain_cython": HERE},
    packages=["aegis_brain_cython"],
    ext_modules=cythonize(
        extensions,
        compiler_directives={
            "language_level": "3",
            "boundscheck": False,
            "wraparound": False,
            "cdivision": True,
            "infer_types": True,
        },
    ),
    zip_safe=False,
)
