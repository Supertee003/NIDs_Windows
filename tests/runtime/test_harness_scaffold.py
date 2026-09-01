"""
test_harness_scaffold.py - Scaffold for the future supervisor harness.

This file is intentionally minimal. It documents the expected interface
of `tests.runtime.harness.start_component()` / `stop_component()` which
will be implemented in a future Gate-B (Integrated) task.

For now it raises NotImplementedError so any test that depends on it
fails loud rather than silently passing.
"""

from __future__ import annotations

import unittest
from typing import Any


def start_component(name: str, **kwargs: Any) -> int:
    """Start a single AEGIS component by name. Returns the PID.

    NOT YET IMPLEMENTED. The future implementation will:
      1. Look up the component in COMPONENTS.
      2. Spawn its binary per LOCAL_RUNBOOK.md.
      3. Write logs/pids/<name>.pid.
      4. Return the PID.

    Implementation is deferred until Gate B (Integrated).
    """
    raise NotImplementedError(
        f"start_component({name!r}) not yet implemented; "
        "live harness arrives at Gate B (Integrated)."
    )


def stop_component(name: str, *, force: bool = False) -> None:
    """Stop a single AEGIS component by name.

    NOT YET IMPLEMENTED. The future implementation will:
      1. Read logs/pids/<name>.pid.
      2. Send SIGINT (Windows: CTRL_C_EVENT).
      3. Wait shutdown_timeout (default 3 s).
      4. If still alive and force=True, SIGKILL / TerminateProcess.
      5. Remove the PID file.
    """
    raise NotImplementedError(
        f"stop_component({name!r}) not yet implemented; "
        "live harness arrives at Gate B (Integrated)."
    )


class TestHarnessNotYetImplemented(unittest.TestCase):
    """These tests document the contract for the future harness. They
    pass today because the harness correctly reports that it is not yet
    implemented."""

    def test_start_component_raises_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            start_component("bridge")

    def test_stop_component_raises_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            stop_component("bridge")


if __name__ == "__main__":
    unittest.main()
