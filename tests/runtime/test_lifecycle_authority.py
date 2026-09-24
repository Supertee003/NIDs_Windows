from __future__ import annotations

import importlib.util
import sys
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from aegisctl import EXIT_RUNTIME_UNAVAILABLE

ENTRYPOINT = REPO_ROOT / "tools" / "aegisctl.py"


def load_entrypoint():
    spec = importlib.util.spec_from_file_location("aegisctl_entrypoint", ENTRYPOINT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeClient:
    calls: list[tuple[str, dict]] = []
    response: dict = {"ok": False, "code": "NOT_IMPLEMENTED", "data": {"message": "supervisor unavailable"}}

    def __init__(self, **kwargs):
        self.transport = kwargs.get("transport")

    def send(self, command: str, payload: dict):
        self.calls.append((command, payload))
        return self.response


class TestLifecycleAuthority(unittest.TestCase):
    def setUp(self):
        FakeClient.calls = []
        self.entrypoint = load_entrypoint()

    def test_start_uses_runtime_control_command(self):
        args = Namespace(component="core", all=False, transport="pipe")
        with patch("aegisctl.client.AegisClient", FakeClient):
            result = self.entrypoint.cmd_start(args)

        self.assertEqual(result, EXIT_RUNTIME_UNAVAILABLE)
        self.assertEqual(FakeClient.calls, [("runtime.start", {"all": False, "component": "core"})])

    def test_start_does_not_create_process_or_pid_file(self):
        args = Namespace(component=None, all=True, transport="pipe")
        with patch("aegisctl.client.AegisClient", FakeClient), \
             patch("subprocess.Popen") as popen:
            result = self.entrypoint.cmd_start(args)

        self.assertEqual(result, EXIT_RUNTIME_UNAVAILABLE)
        popen.assert_not_called()

    def test_success_is_returned_only_from_daemon_response(self):
        FakeClient.response = {"ok": True, "code": "OK", "data": {"state": "RUNNING"}}
        args = Namespace(component=None, all=True, transport="pipe")
        with patch("aegisctl.client.AegisClient", FakeClient):
            result = self.entrypoint.cmd_start(args)

        self.assertEqual(result, 0)
        self.assertEqual(FakeClient.calls[0][0], "runtime.start")

    def test_stop_requests_orderly_daemon_shutdown(self):
        FakeClient.response = {"ok": True, "code": "OK", "data": {"shutdown": True}}
        args = Namespace(component=None, all=True, transport="pipe")
        with patch("aegisctl.client.AegisClient", FakeClient), \
             patch("subprocess.run") as run:
            result = self.entrypoint.cmd_stop(args)

        self.assertEqual(result, 0)
        self.assertEqual(FakeClient.calls, [("daemon.shutdown", {"all": True, "component": None})])
        run.assert_not_called()

    def test_restart_never_performs_partial_stop_or_start(self):
        args = Namespace(component="core", transport="pipe")
        with patch("aegisctl.client.AegisClient", FakeClient):
            result = self.entrypoint.cmd_restart(args)

        self.assertEqual(result, 4)
        self.assertEqual(FakeClient.calls, [])


if __name__ == "__main__":
    unittest.main()
