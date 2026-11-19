"""FP-FEEDBACK-001: operator mark-fp is advisory, local, and never gates detection.

Every write goes to AEGIS_LOGS_DIR (tmp_path here); no daemon pipe is contacted,
no rule/policy/forensic file is touched, and no test writes to the tracked tree.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"


def _load_cli():
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    spec = importlib.util.spec_from_file_location("aegisctl_markfp_under_test", TOOLS_DIR / "aegisctl.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = _load_cli()
feedback = cli.fp_feedback


def test_mark_fp_appends_one_validated_record_and_reports_count(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_LOGS_DIR", str(tmp_path))
    result = feedback.append_event(42, reason='looks like "scan"\nnext line')
    assert result["ok"] is True and result["persisted"] is True
    assert result["event_id"] == 42 and result["count"] == 1
    assert "fp_feedback.ndjson" in result["path"]

    path = tmp_path / "fp_feedback.ndjson"
    raw = path.read_text(encoding="utf-8")
    assert raw.count("\n") == 1  # exactly one line, newline sanitized
    record = json.loads(raw)
    assert record["schema"] == "aegis.fp_feedback.v1"
    assert record["event_id"] == 42
    assert "\n" not in record["reason"] and '\\"' in raw  # escaped quote stays valid JSON


def test_mark_fp_postcondition_proves_persistence(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_LOGS_DIR", str(tmp_path))
    result = feedback.append_event(7)
    assert feedback.count() == 1
    assert feedback.read_all()[0]["ts_ms"] == result["ts_ms"]


def test_mark_fp_rejects_invalid_event_ids_without_writing(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_LOGS_DIR", str(tmp_path))
    for bad in (0, -1, "42", 1.5, True, None):
        try:
            feedback.append_event(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid event_id accepted: {bad!r}")
    assert not (tmp_path / "fp_feedback.ndjson").exists()


def test_reason_is_bounded_and_control_chars_are_stripped(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_LOGS_DIR", str(tmp_path))
    feedback.append_event(9, reason="x" * 1000 + "\r\n\t")
    stored = feedback.read_all()[0]["reason"]
    assert len(stored) == 256
    assert "\r" not in stored and "\n" not in stored


def test_mark_fp_never_contacts_the_daemon(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AEGIS_LOGS_DIR", str(tmp_path))

    def forbidden(*_args, **_kwargs):
        raise AssertionError("mark-fp must not query the control pipe")

    monkeypatch.setattr(cli, "query_control", forbidden, raising=False)
    monkeypatch.setattr(sys, "argv", ["aegisctl.py", "mark-fp", "123", "--reason", "benign"])
    assert cli.main() == 0
    out = capsys.readouterr().out
    assert '"ok": true' in out or '"ok":true' in out
    assert feedback.count() == 1


def test_fp_count_prints_advisory_local_count(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AEGIS_LOGS_DIR", str(tmp_path))
    feedback.append_event(1)
    feedback.append_event(2)
    monkeypatch.setattr(sys, "argv", ["aegisctl.py", "fp", "count"])
    assert cli.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 2
    assert payload["source"] == "local_log"
    assert payload["advisory"] is True


def test_mark_fp_invalid_id_returns_nonzero(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AEGIS_LOGS_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["aegisctl.py", "mark-fp", "-3"])
    assert cli.main() == 2
    assert not (tmp_path / "fp_feedback.ndjson").exists()
