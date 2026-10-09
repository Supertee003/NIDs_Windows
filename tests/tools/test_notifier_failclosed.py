"""DB/SEC/EXT sweep: webhook fail-closed pin.

notify_webhook must refuse when the signing secret is absent (an
empty-key HMAC authenticates nothing). Both pins return before any
network I/O: no URL configured, and URL set with no secret.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


def _load_notifier():
    path = Path(__file__).resolve().parents[2] / "scripts" / "aegis_notifier.py"
    spec = importlib.util.spec_from_file_location("aegis_notifier_under_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["aegis_notifier_under_test"] = module
    spec.loader.exec_module(module)
    return module


notifier = _load_notifier()


def test_webhook_refuses_without_url(monkeypatch):
    monkeypatch.delenv("AEGIS_NOTIFIER_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("AEGIS_NOTIFIER_WEBHOOK_SECRET", raising=False)
    assert notifier.notify_webhook({"test": 1}) is False


def test_webhook_refuses_without_secret(monkeypatch):
    monkeypatch.setenv("AEGIS_NOTIFIER_WEBHOOK_URL", "http://127.0.0.1:9/hook")
    monkeypatch.delenv("AEGIS_NOTIFIER_WEBHOOK_SECRET", raising=False)
    assert notifier.notify_webhook({"test": 1}) is False
