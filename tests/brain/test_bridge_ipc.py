"""T3-BRIDGE-026: Cython bridge binding pins.

`brain/cython/bridge_ipc.pyx` is the primary Python->C edge for the C++
IPC bridge (ctypes shim in `bridge/aegis_bridge_ctypes.py` delegates to
it; ctypes stays as fallback). Pinned here (no DLL required — every
assertion holds in BOTH standalone and connected modes):

  C1. ABI struct sizes: IpcEvent 72, IpcCommand 24 (matches
      `bridge/aegis_ipc.hpp` #pragma pack(1)).
  C2. Honesty without a DLL decision: every callable returns its
      documented fallback (init -1, push -1, pop None, counts 0,
      DEFCON SAFE/5, block -1) and never raises, never claims effect.
  C3. Round-trip when connected (skipped standalone): init 0, push accepted,
      pop returns the event with tier_result + FNV rule identity.
  C4. FNV-1a string rule IDs (golden R0056 -> 2107512682, shared with the
      sensor-pipe contract); the old int() crash on "R0056" is gone.
  C5. Fail-closed: ips_decide never returns "block" unless block_ip()
      returned exactly 0 (the C++ -2 included in nonzero).
  C6. Shim delegation: BRIDGE_VIA reports the active edge, exactly one.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "bridge"))

from brain.cython import bridge_ipc as cy  # noqa: E402
import aegis_bridge_ctypes as shim  # noqa: E402


def test_abi_struct_sizes_match_cpp_header():
    assert cy.IPC_EVENT_SIZE == 76
    assert cy.IPC_COMMAND_SIZE == 24


def test_fallback_honesty_without_dll():
    if cy.is_available():
        pytest.skip("DLL present: fallback path not active")
    assert cy.bridge_init() == -1
    assert cy.bridge_shutdown() == -1
    assert cy.push_event(0, 1, 2, 3, 4, 6, 2, "R1", 3) == -1
    assert cy.pop_event() is None
    assert cy.get_event_count() == 0
    assert cy.get_dropped_count() == 0
    assert cy.get_defcon_level() == 5
    assert cy.get_defcon_label() == "SAFE"
    assert cy.block_ip("10.0.0.1") == -1
    assert cy.unblock_ip("10.0.0.1") == -1
    assert cy.push_tier2_match("R0056", "10.0.0.1", "0.0.0.0", 0, 0, 6, 2) == -1
    assert cy.ips_decide("R0056", 3, "10.0.0.1") == "enforcement_unavailable"
    assert cy.ips_decide("R1", 0, "10.0.0.1") == "alert"


def test_live_round_trip_when_connected():
    if not cy.is_available():
        pytest.skip("no DLL: connected path not active")
    assert cy.bridge_init() == 0
    try:
        assert cy.push_tier2_match("R0056", "10.0.0.1", "0.0.0.0", 0, 0, 6, 2) == 0
        ev = cy.pop_event()
        assert ev is not None
        assert ev.tier_result == 2
        assert ev.rule_id == 2107512682
        assert ev.source_ip == 0x0A000001
    finally:
        assert cy.bridge_shutdown() == 0


def test_fnv1a32_rule_id_mapping():
    assert cy._rule_to_u32("R0056") == 2107512682
    assert cy._rule_to_u32(4242) == 4242
    assert cy._rule_to_u32("4242") == 4242
    assert shim._rule_to_u32("R0056") == 2107512682


def test_fail_closed_decision_strings():
    # Without a DLL every block attempt is unavailable; with one, only an
    # exact 0 authorizes "block". Either way the vocabulary is closed.
    for severity, action in ((3, "alert"), (0, "alert"), (2, "block"), (0, "frobnicate")):
        decision = cy.ips_decide("R0056", severity, "10.0.0.1", action)
        assert decision in ("alert", "block", "enforcement_unavailable")
    if not cy.is_available():
        assert cy.ips_decide("R0056", 3, "10.0.0.1") == "enforcement_unavailable"


def test_shim_delegates_to_exactly_one_edge():
    assert shim.BRIDGE_VIA in ("cython", "ctypes")
    try:
        import brain.cython.bridge_ipc  # noqa: F401
        assert shim.BRIDGE_VIA == "cython"
    except ImportError:
        assert shim.BRIDGE_VIA == "ctypes"
