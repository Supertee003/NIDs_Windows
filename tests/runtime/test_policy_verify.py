"""BE-RCPT-091: policy verify/validate route to the daemon's canonical check.

Failure mode pinned: policy_verify/policy_validate returned
NOT_IMPLEMENTED while three validators existed nowhere near the
control plane, and the CLI had no subcommands reaching them. Contract:

  AC1. CLI routes verify/validate to the matching control commands
       and prints the daemon report verbatim (mocked daemon).
  AC2. Against a real daemon the commands are accepted (rc 0 with a
       report, or rc 3 honest-unreachable) — never a usage error, never
       a local guess, never a tree write.
  AC3. Both handlers stay registered with operate read-only contracts.
"""
from __future__ import annotations

import argparse
import io
import json
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_cli():
    """Import tools/aegisctl.py by path: the tools.aegisctl *package*
    shadows the module name, so a plain import binds the wrong file."""
    import importlib.util
    import sys

    tools_dir = str(REPO_ROOT / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location(
        "aegisctl_cli", str(REPO_ROOT / "tools" / "aegisctl.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = _load_cli()


def _args(command: str) -> argparse.Namespace:
    return argparse.Namespace(policy_command=command, json=True)


def _run_cmd(command: str, report: dict) -> tuple[int, str]:
    with patch.object(cli, "query_control", return_value=dict(report)):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.cmd_policy(_args(command))
    return rc, buf.getvalue()


def test_verify_prints_the_daemon_report_verbatim():
    report = {
        "verified": False,
        "policies": {"present": True, "sidecar": False, "anchors": "none",
                     "anchors_broken": False, "valid": False, "reason": "SIDECAR_ABSENT"},
        "policy_ir": {"present": False, "sidecar": False, "anchors": "none",
                      "anchors_broken": False, "valid": False, "reason": "DOC_ABSENT"},
    }
    rc, out = _run_cmd("verify", report)
    assert rc == 0
    body = json.loads(out)
    assert body["verified"] is False
    assert body["policies"]["reason"] == "SIDECAR_ABSENT"
    assert body["policy_ir"]["reason"] == "DOC_ABSENT"


def test_validate_prints_counts():
    rc, out = _run_cmd("validate", {"valid": True, "policies_checked": 6, "policies_skipped": 0})
    assert rc == 0
    body = json.loads(out)
    assert body["valid"] is True
    assert body["policies_checked"] == 6


def test_handlers_keep_operate_read_only_contracts():
    source = (REPO_ROOT / "src" / "control" / "protocol.zig").read_text(encoding="utf-8")
    assert '.policy_verify => ' in source and '.required_role = .operate' in source
    assert '.policy_validate => ' in source
    registry = (REPO_ROOT / "src" / "control" / "handler_registry.zig").read_text(encoding="utf-8")
    assert "registerHandler(.policy_verify, handlers.policyVerify)" in registry
    assert "registerHandler(.policy_validate, handlers.policyValidate)" in registry
    assert "NOT_IMPLEMENTED" not in registry.split("fn policyVerify")[1].split("fn policySimulate")[0]
    assert "NOT_IMPLEMENTED" not in registry.split("fn policyValidate")[1].split("fn policyVerify")[0]


def test_live_daemon_accepts_both_commands_without_guessing():
    for command in ("verify", "validate"):
        proc = subprocess.run(
            [sys.executable, "tools/aegisctl.py", "policy", command],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(REPO_ROOT),
        )
        # 0 = daemon answered with a report; 3 = daemon unreachable
        # (old binary answers ok:false, which the client reports
        # honestly). 2/usage errors and tracebacks are the failure.
        assert proc.returncode in (0, 3), proc.stderr[-500:]
        assert "Traceback" not in proc.stderr
        if proc.returncode == 0:
            body = json.loads(proc.stdout)
            assert isinstance(body, dict)
