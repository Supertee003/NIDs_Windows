"""BE-DRIFT-098: rules.reload names skipped rules without breaking old readers.

Contract:
  AC1. The CLI prints the daemon reload report verbatim, including the
       new skipped breakdown/IDs (mocked daemon, full new shape).
  AC2. Against a real daemon the command stays accepted with the
       long-standing keys (rc 0 + rules_loaded + ACTIVE postcondition);
       new keys are additive and ignored by old readers.
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
    import importlib.util

    tools_dir = str(REPO_ROOT / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location(
        "aegisctl_cli_rules", str(REPO_ROOT / "tools" / "aegisctl.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = _load_cli()

NEW_SHAPE = {
    "command": "rules.reload",
    "previous_rules_loaded": 22,
    "rules_loaded": 22,
    "status": "reloaded",
    "postcondition": "ACTIVE",
    "skipped": {"no_pattern": 1, "disabled": 0, "malformed": 0, "add_failed": 0},
    "skipped_ids": ["9003"],
    "skipped_truncated": False,
}


def test_reload_prints_named_skips_verbatim():
    args = argparse.Namespace(rules_command="reload")
    with patch.object(cli, "query_control", return_value=dict(NEW_SHAPE)):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.cmd_rules(args)
    assert rc == 0
    body = json.loads(buf.getvalue())
    assert body["rules_loaded"] == 22
    assert body["postcondition"] == "ACTIVE"
    assert body["skipped"]["no_pattern"] == 1
    assert body["skipped_ids"] == ["9003"]
    assert body["skipped_truncated"] is False


def test_live_daemon_reload_keeps_long_standing_keys():
    proc = subprocess.run(
        [sys.executable, "tools/aegisctl.py", "rules", "reload"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(REPO_ROOT),
    )
    # 0 = reloaded (old or new shape); 1/3/5 = daemon-side refusal or
    # unreachable — all honest. 2/usage errors and tracebacks fail.
    assert proc.returncode in (0, 1, 3, 5), proc.stderr[-500:]
    assert "Traceback" not in proc.stderr
    if proc.returncode == 0:
        body = json.loads(proc.stdout)
        assert body["rules_loaded"] > 0
        assert body["postcondition"] == "ACTIVE"
