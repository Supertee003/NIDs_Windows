# setup.py — Build Cython hotspots for AEGIS NIDS
from setuptools import setup
from Cython.Build import cythonize
import numpy as np

setup(
    name="aegis_hotspots",
    ext_modules=cythonize(
        "aegis_hotspots.pyx",
        compiler_directives={
            'language_level': "3",
            'boundscheck': False,
            'wraparound': False,
            'cdivision': True,
            'initializedcheck': False,
        },
        include_path=[np.get_include()],
    ),
)
