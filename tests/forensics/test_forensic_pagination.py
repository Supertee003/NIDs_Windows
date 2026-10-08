"""FORENSIC-PAGE-001: forensic queries must page, never truncate or hard-fail.

The daemon owns one message-mode control pipe and every canonical client reads
at most one buffer per ReadFile. A ``forensics.list --limit 1000`` response
serialized to >100 KB, so a client that treated the first read as the whole
response reported ``Control query failed`` (rc=3) for a perfectly healthy
forensic ring. The fix is two-sided: the daemon bounds every page by a byte
budget and reports a continuation cursor, and clients accumulate reads until a
single JSON document parses.

Contract pinned here:
  AC1. The daemon bounds every forensic page by a byte budget and reports
       `truncated` plus a `next_after` cursor instead of an unbounded body.
  AC2. The canonical client accumulates reads until one JSON document parses;
       a partial read is never reported as a transport failure.
  AC3. `query_forensic_records` follows the cursor until the result set is
       complete and reports `truncated` (never a silently short list) when a
       page cap or budget is exhausted.
  AC4. The CLI exposes `--all`, and the evidence graph uses it and refuses to
       render a partial (truncated) result set.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.aegisctl.api import control_api

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
HANDLER = REPO_ROOT / "src" / "control" / "handler_registry.zig"
CLI = REPO_ROOT / "tools" / "aegisctl.py"
GRAPH = REPO_ROOT / "scripts" / "aegis_graph.py"


# ── AC1: daemon page budget + explicit continuation ────────────────────────

def test_daemon_page_is_byte_budgeted():
    source = HANDLER.read_text(encoding="utf-8")
    assert "FORENSIC_PAGE_DEFAULT_BYTES" in source
    assert "FORENSIC_PAGE_DEFAULT_BYTES: u64 = 32 * 1024" in source
    assert "FORENSIC_ENTRY_MAX_BYTES" in source
    assert "FORENSIC_FOOTER_BYTES" in source
    assert "> requested_budget" in source, (
        "the handler must stop writing before the response crosses the page budget"
    )
    for field in ('\\"truncated\\"', '\\"next_after\\"', '\\"records_matched\\"', '\\"max_bytes\\"'):
        assert field in source, f"forensics.list response is missing {field}"
    # Both response branches must carry the same page contract so a caller can
    # always read `truncated`/`next_after` without a KeyError.
    unavailable = source.split('"{\\"available\\":false', 1)[1].split("}", 1)[0]
    assert "truncated" in unavailable and "next_after" in unavailable


# ── AC2: client accumulation ───────────────────────────────────────────────

def test_partial_read_is_never_a_complete_document():
    assert control_api._response_document_complete(b"") is False
    assert control_api._response_document_complete(b'{"ok":true,"data":{') is False
    assert control_api._response_document_complete(b'{"ok":true,"da') is False
    assert control_api._response_document_complete(b'{"ok":true,"data":{}}') is True
    # Two concatenated documents are not one document (json rejects extra data).
    assert control_api._response_document_complete(b'{"a":1}{"b":2}') is False


def test_pipe_client_keeps_reading_until_the_document_parses():
    source = (REPO_ROOT / "tools" / "aegisctl" / "api" / "control_api.py").read_text(
        encoding="utf-8"
    )
    assert control_api.ERROR_MORE_DATA == 234
    assert control_api.ERROR_BROKEN_PIPE == 109
    assert "ERROR_MORE_DATA" in source
    assert "_response_document_complete(b\"\".join(chunks))" in source, (
        "the read loop must decide completion from a parsed document, not from a"
        " single ok ReadFile"
    )
    # The legacy pattern that produced the rc=3 failure must not survive.
    assert "if ok or ctypes.get_last_error() == 109" not in source


def test_pywin32_client_does_not_lose_the_message_remainder():
    source = (REPO_ROOT / "tools" / "aegisctl" / "client.py").read_text(encoding="utf-8")
    assert "PeekNamedPipe" in source, (
        "message-mode reads must be sized to the bytes left in the message"
    )
    assert "win32file.ReadFile(handle, 65536)" not in source, (
        "a fixed-size read loses the remainder of a larger message"
    )
    assert "ERROR_MORE_DATA" in source


# ── AC3: cursor-following pagination ───────────────────────────────────────

def _page(records, *, truncated, next_after, integrity="ok", verified=True):
    return {
        "available": True,
        "records": records,
        "records_returned": len(records),
        "records_matched": len(records),
        "truncated": truncated,
        "next_after": next_after,
        "integrity": integrity,
        "verified": verified,
    }


def test_pagination_follows_cursor_to_a_complete_result_set(monkeypatch):
    calls: list[dict] = []
    pages = [
        _page([{"record_seq": 1}, {"record_seq": 2}], truncated=True, next_after=2),
        _page([{"record_seq": 3}], truncated=False, next_after=None),
    ]

    def fake_query(command, payload=None):
        calls.append({"command": command, "payload": dict(payload or {})})
        return pages[min(len(calls) - 1, len(pages) - 1)]

    monkeypatch.setattr(control_api, "query_control", fake_query)
    document = control_api.query_forensic_records(10)

    assert document is not None
    assert [r["record_seq"] for r in document["records"]] == [1, 2, 3]
    assert document["records_returned"] == 3
    assert document["pages"] == 2
    assert document["truncated"] is False
    assert document["next_after"] is None
    assert [call["payload"].get("after") for call in calls] == [None, 2]
    assert all(call["command"] == "forensics.list" for call in calls)
    assert all(payload["limit"] <= 1000 for payload in (c["payload"] for c in calls))


def test_pagination_reports_incomplete_instead_of_silent_short_list(monkeypatch):
    def fake_query(command, payload=None):
        return _page([{"record_seq": 7}], truncated=True, next_after=None)

    monkeypatch.setattr(control_api, "query_control", fake_query)
    document = control_api.query_forensic_records(10)

    assert document is not None
    assert document["truncated"] is True, "an uncontinuable page must not claim completeness"
    assert document["records_returned"] == 1


def test_pagination_stops_at_the_requested_limit(monkeypatch):
    calls: list[dict] = []

    def fake_query(command, payload=None):
        calls.append(dict(payload or {}))
        after = int(payload.get("after") or 0)
        wanted = int(payload["limit"])
        records = [{"record_seq": after + 1 + i} for i in range(min(wanted, 2))]
        return _page(records, truncated=True, next_after=after + len(records))

    monkeypatch.setattr(control_api, "query_control", fake_query)
    document = control_api.query_forensic_records(3)

    assert document is not None
    assert document["records_returned"] == 3
    assert document["truncated"] is True
    assert document["next_after"] == 3, "the continuation cursor must be honest"


def test_pagination_propagates_unavailable_control_plane(monkeypatch):
    monkeypatch.setattr(control_api, "query_control", lambda *a, **k: None)
    assert control_api.query_forensic_records(10) is None


# ── AC4: CLI + graph wiring ────────────────────────────────────────────────

def test_cli_exposes_all_flag_and_graph_uses_it():
    cli_source = CLI.read_text(encoding="utf-8")
    assert '"--all"' in cli_source
    assert "query_forensic_records(" in cli_source
    assert "page_budget_exhausted" in cli_source

    graph_source = GRAPH.read_text(encoding="utf-8")
    assert '"--all"' in graph_source
    assert "refusing to render a partial graph" in graph_source


@pytest.mark.skipif(sys.platform != "win32", reason="named pipes are Windows-only")
def test_large_control_response_is_accumulated_across_message_reads(monkeypatch, tmp_path):
    """Regression: a response larger than one read buffer must still parse.

    This reproduces the original failure directly: a message-mode control
    response of ~150 KB (the size a 1000-record forensic page reached) written
    in three chunks. The legacy client read one buffer, saw a partial document
    and reported `Control query failed`; the canonical client must accumulate
    reads until the JSON document parses.
    """
    import threading
    import uuid

    import win32file  # type: ignore
    import win32pipe  # type: ignore

    pipe_name = rf"\\.\pipe\aegis_pagination_test_{uuid.uuid4().hex[:12]}"
    listening = threading.Event()
    records = [{"record_seq": i, "payload": "x" * 64} for i in range(1200)]
    document = json.dumps({
        "ok": True,
        "code": "OK",
        "data": {
            "available": True,
            "records": records,
            "records_returned": len(records),
            "integrity": "ok",
            "verified": True,
        },
    }).encode("utf-8")
    assert len(document) > 100 * 1024, "the fixture must exceed one 64 KiB read"
    failures: list[Exception] = []

    def serve() -> None:
        try:
            handle = win32pipe.CreateNamedPipe(
                pipe_name,
                0x00000003,                      # PIPE_ACCESS_DUPLEX
                0x00000004 | 0x00000002,         # PIPE_TYPE_MESSAGE | READMODE_MESSAGE
                1, 65536, 65536, 0, None,
            )
            try:
                listening.set()
                win32pipe.ConnectNamedPipe(handle, None)
                win32file.ReadFile(handle, 65536)
                for offset in range(0, len(document), 50000):
                    _, written = win32file.WriteFile(handle, document[offset:offset + 50000])
                    assert written > 0
            finally:
                try:
                    win32pipe.DisconnectNamedPipe(handle)
                except Exception:
                    pass
                win32file.CloseHandle(handle)
        except Exception as exc:  # pragma: no cover - surfaced by the assertion below
            failures.append(exc)

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    assert listening.wait(timeout=5), "named-pipe fixture never started listening"
    monkeypatch.setattr(control_api, "CONTROL_PIPE", pipe_name)
    try:
        response = control_api._query_daemon("forensics.list", {"limit": 1000})
    finally:
        server.join(timeout=10)
    assert not failures, f"named-pipe fixture failed: {failures}"
    assert response is not None, (
        "a large response must not read as a control failure "
        f"({len(document)} bytes over {pipe_name})"
    )
    assert response["verified"] is True
    assert len(response["records"]) == len(records)


def _daemon_available() -> bool:
    if sys.platform != "win32":
        return False
    return control_api.query_control("system.health") is not None


@pytest.mark.skipif(not _daemon_available(), reason="control daemon not running")
def test_live_daemon_serves_a_full_1000_record_page():
    """Regression: `--limit 1000 --all` must not fail with 'Control query failed'."""
    completed = subprocess.run(
        [sys.executable, str(CLI), "forensics", "list", "--limit", "1000", "--all", "--json"],
        cwd=REPO_ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    assert completed.returncode == 0, completed.stderr
    document = json.loads(completed.stdout)
    assert document["available"] is True
    assert document["integrity"] == "ok"
    assert document["verified"] is True
    assert document["records_returned"] == len(document["records"])
    assert document["records_returned"] <= 1000
    if document["truncated"]:
        # Ring holds more than the requested limit: the client stops at
        # exactly the limit with an honest continuation cursor (the pinned
        # unit behavior of test_pagination_stops_at_the_requested_limit),
        # never a silently short list.
        assert document["records_returned"] == 1000
        assert document["next_after"] is not None
    else:
        # Small ring: the result set completed; no cursor may remain.
        assert document["next_after"] is None
