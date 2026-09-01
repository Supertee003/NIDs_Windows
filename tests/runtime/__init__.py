"""
AEGIS NIDS - Runtime Contract Tests
====================================

This package contains contract tests that verify every runnable component
honors the runtime contract defined in `docs/runtime/RUNTIME_CONTRACT.md`.

Each test module covers one slice of the contract:

  test_states.py        - lifecycle state transitions (STOPPED/STARTING/READY/
                          RUNNING/DEGRADED/FAILED) per LIFECYCLE.md
  test_timeouts.py      - startup/ready/shutdown/degrade timeouts per
                          RUNTIME_CONTRACT.md §3
  test_health.py        - health probe transports and schema (§4)
  test_restart.py       - exponential backoff, max-restarts, quarantine (§5)
  test_wire.py          - STATUS / HEALTH / ERROR / STARTING_PROGRESS envelopes
                          (§6) and error-class closed set
  test_version.py       - every component exposes --version (COMPONENT_MATRIX §7)
  test_component_matrix.py - every row of COMPONENT_MATRIX.md has a matching
                             test entry and a startup method

These tests are NOT gate-A unit tests; they are runtime/operational tests
that exercise a real (or simulated) component process. They are intended to
be executed by the supervisor's CI stage "runtime-contract" AFTER the
build stage and BEFORE the integration stage.

Run them from the repo root with:

    python -m pytest tests/runtime/ -v

Or, if pytest is not yet installed:

    python -m unittest discover -s tests/runtime -v
"""

__version__ = "1.0.0"

# Public registry of contract-test modules. Each entry maps a contract
# section to its test module so the supervisor can run a subset.
CONTRACT_TEST_MODULES = {
    "states":   "tests.runtime.test_states",
    "timeouts": "tests.runtime.test_timeouts",
    "health":   "tests.runtime.test_health",
    "restart":  "tests.runtime.test_restart",
    "wire":     "tests.runtime.test_wire",
    "version":  "tests.runtime.test_version",
    "matrix":   "tests.runtime.test_component_matrix",
}

__all__ = ["CONTRACT_TEST_MODULES"]
