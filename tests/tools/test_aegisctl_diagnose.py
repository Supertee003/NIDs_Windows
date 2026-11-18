"""EVT-218: `aegisctl.py diagnose` renders the worker `failed` flag honestly.

The daemon's health payload carries `workers.failed` as an aggregate boolean
flag (the readiness gate reads `workers.get("failed", False)`), not as a
worker slot. The diagnose renderer looped over every key and only special-
cased `failure_reason` / `failure_mask` / `failure_reasons`, so the boolean
fell into the generic branch and printed `[NOT READY] failed` on a healthy
host (observed live: Degraded: False, MASK 0, REASONS none).

Pins:
  - healthy payload -> `[FAILED] no`, and `[NOT READY] failed` never appears;
  - failed=true payload -> `[FAILED] yes` plus its reason fields (the flag
    is surfaced, not hidden);
  - worker slots keep their READY / NOT READY rendering.

Read-only: imports the CLI module by path (guarded, no side effects),
stubs the control API in-process, writes nothing to the tree, contacts
no daemon.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import types
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"


def _load_cli():
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    spec = importlib.util.spec_from_file_location(
        "aegisctl_diagnose_under_test", TOOLS_DIR / "aegisctl.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["aegisctl_diagnose_under_test"] = module
    spec.loader.exec_module(module)
    return module


cli = _load_cli()


def _payload(**worker_overrides):
    workers = {
        "pipeline_ready": True,
        "sensor_ready": True,
        "nose_ready": True,
        "etw_ready": True,
        "fim_ready": True,
        "registry_ready": True,
        "failed": False,
        "failure_reason": "none",
        "failure_mask": 0,
        "failure_reasons": [],
    }
    workers.update(worker_overrides)
    return {
        "version": "5.0.0",
        "state": "RUNNING",
        "degraded": False,
        "subsystems": {"zig": {"state": "RUNNING"}},
        "tier3": {"state": "READY"},
        "workers": workers,
    }


def _run_diagnose(monkeypatch, payload):
    monkeypatch.setattr(cli, "CONTROL_API_AVAILABLE", True)
    monkeypatch.setattr(cli, "get_health_payload", lambda: payload)
    monkeypatch.setattr(
        cli, "diagnose_endpoint_ownership",
        lambda: {"findings": [], "foreign_count": 0},
    )
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli.cmd_diagnose(types.SimpleNamespace())
    return rc, buf.getvalue()


def test_healthy_host_renders_failed_flag_honestly(monkeypatch):
    rc, out = _run_diagnose(monkeypatch, _payload())
    assert rc == 0
    assert "[FAILED] no" in out
    assert "[NOT READY] failed" not in out
    assert "[READY] pipeline_ready" in out
    assert "[MASK] 0" in out
    assert "Diagnostic report complete" in out


def test_failed_flag_true_is_surfaced(monkeypatch):
    rc, out = _run_diagnose(
        monkeypatch,
        _payload(failed=True, failure_reason="pipeline_timeout",
                 failure_mask=1, failure_reasons=["pipeline_timeout"]),
    )
    assert rc == 0
    assert "[FAILED] yes" in out
    assert "[REASON] pipeline_timeout" in out
    assert "[REASONS] pipeline_timeout" in out


def test_not_ready_worker_still_renders_not_ready(monkeypatch):
    rc, out = _run_diagnose(monkeypatch, _payload(nose_ready=False))
    assert rc == 0
    assert "[NOT READY] nose_ready" in out
    assert "[FAILED] no" in out
