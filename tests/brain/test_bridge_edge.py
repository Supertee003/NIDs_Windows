"""T3-BRIDGE-026b: brain connects through the Cython bridge edge.

The brain prefers `brain.cython.bridge_ipc`, falls back to the ctypes
shim (which itself delegates to Cython when built), else standalone.
Pinned here:

  R1. Exactly one edge is active and named by BRIDGE_VIA.
  R2. When the Cython module is importable, the brain uses it (not the
      ctypes shim directly).
  R3. Fallback order never raises: with no .pyd and no shim import path,
      the brain still imports with BRIDGE_AVAILABLE False.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

import brain.windows_brain as brain  # noqa: E402


def test_exactly_one_bridge_edge_named():
    assert brain.BRIDGE_VIA in ("cython", "ctypes", "none")
    assert brain.BRIDGE_AVAILABLE == (brain.BRIDGE_VIA != "none")


def test_cython_edge_preferred_when_built():
    try:
        from brain.cython import bridge_ipc  # noqa: F401
    except ImportError:
        import pytest

        pytest.skip("bridge_ipc.pyd not built")
    assert brain.BRIDGE_VIA == "cython"
    assert brain.bridge is bridge_ipc


def test_bridge_api_surface_complete_on_active_edge():
    if not brain.BRIDGE_AVAILABLE:
        import pytest

        pytest.skip("standalone mode: no edge active")
    for name in ("bridge_init", "bridge_shutdown", "push_event", "pop_event",
                 "get_event_count", "get_dropped_count", "get_defcon_level",
                 "get_defcon_label", "push_tier2_match", "ips_decide"):
        assert callable(getattr(brain.bridge, name)), name
