"""Unit + loopback tests for the TAXII 2.1 push client.

The test server binds 127.0.0.1 on an ephemeral port only; no test ever
reaches an external host. This proves the advisory push transport at E2 and
nothing about detection behavior.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS_DIR))

from taxii_push import (  # noqa: E402
    ENV_URL,
    TaxiiError,
    basic_auth_header,
    main,
    objects_url,
    push_bundle,
    validate_bundle_payload,
)


# ---------------------------------------------------------------------------
# Loopback TAXII stub
# ---------------------------------------------------------------------------

class _StubHandler(BaseHTTPRequestHandler):
    status = 202  # tests mutate this class attribute

    def do_POST(self):  # noqa: N802 (http.server API)
        self.server.requests.append((self.path, self.headers.get("Content-Type"),
                                     self.headers.get("Accept"),
                                     self.headers.get("Authorization")))
        # Drain the request body before replying. Closing a socket with unread
        # data makes Windows reset the connection (WinError 10053), which can
        # hide the stub's status behind a transport error when the client is
        # still writing. A real TAXII server consumes the bundle first.
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        body = b"{}"
        self.send_response(self.status)
        self.send_header("Content-Type", "application/taxii+json;version=2.1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence request logging
        pass


@pytest.fixture()
def taxii_stub():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _StubHandler.status = 202
    yield server, f"http://127.0.0.1:{server.server_port}/taxii2/"
    server.shutdown()
    server.server_close()


BUNDLE = {
    "type": "bundle",
    "id": "bundle--ad4ea5be-bbb7-4ab6-b94f-b2e0a5a6f9f8",
    "objects": [
        {"type": "ipv4-addr", "spec_version": "2.1",
         "id": "ipv4-addr--3e4bf3ba-c823-5f9e-9f74-c7a45e6b14f5",
         "value": "185.199.109.133"},
        {"type": "observed-data", "spec_version": "2.1",
         "id": "observed-data--b43bbd26-5c5e-425c-81dd-1f9d889a82a1",
         "created": "2026-11-05T10:03:16.856Z",
         "modified": "2026-11-05T10:03:16.856Z",
         "first_observed": "2026-11-05T10:03:16.856Z",
         "last_observed": "2026-11-05T10:03:16.856Z",
         "number_observed": 1,
         "object_refs": ["ipv4-addr--3e4bf3ba-c823-5f9e-9f74-c7a45e6b14f5"]},
    ],
}


# ---------------------------------------------------------------------------
# Pure builders
# ---------------------------------------------------------------------------

def test_objects_url_builds_collection_endpoint():
    assert objects_url("https://taxii.example.com/taxii2/", "abc123") == \
        "https://taxii.example.com/taxii2/collections/abc123/objects/"


@pytest.mark.parametrize("base,coll", [
    ("", "abc"),                        # empty base
    ("taxii.example.com", "abc"),       # no scheme
    ("https://x/t", ""),                # empty collection
    ("https://x/t", "a/b"),             # fragment injection
    ("https://x/t", "a b"),
    ("https://x/t/collections/abc", "def"),  # collection already in base
])
def test_objects_url_rejects_bad_input(base, coll):
    with pytest.raises(TaxiiError):
        objects_url(base, coll)


def test_basic_auth_header_matches_expected_64():
    expected = "Basic " + base64.b64encode(b"u:p").decode()
    assert basic_auth_header("u", "p") == expected


# ---------------------------------------------------------------------------
# Payload validation gate
# ---------------------------------------------------------------------------

def test_validate_refuses_non_bundle_and_empty():
    with pytest.raises(TaxiiError):
        validate_bundle_payload({"type": "observed-data"})
    with pytest.raises(TaxiiError):
        validate_bundle_payload({**BUNDLE, "objects": []})
    with pytest.raises(TaxiiError):
        validate_bundle_payload(None)
    broken = {**BUNDLE, "objects": [{"type": "ipv4-addr"}]}  # required keys missing
    with pytest.raises(TaxiiError):
        validate_bundle_payload(broken)


# ---------------------------------------------------------------------------
# push_bundle against the loopback stub
# ---------------------------------------------------------------------------

def test_push_bundle_202_roundtrip(taxii_stub):
    server, base = taxii_stub
    status, _ = push_bundle(BUNDLE, base, "coll1", username="u", password="p")
    assert status == 202
    path, ctype, accept, auth = server.requests[0]
    assert path == "/taxii2/collections/coll1/objects/"
    assert ctype == "application/stix+json;version=2.1"
    assert accept == "application/taxii+json;version=2.1"
    assert auth.startswith("Basic ")
    assert base64.b64decode(auth.split()[1]).decode() == "u:p"


def test_push_bundle_without_credentials_is_anonymous(taxii_stub):
    server, base = taxii_stub
    status, _ = push_bundle(BUNDLE, base, "coll1")
    assert status == 202
    assert server.requests[0][3] is None


def test_push_bundle_200_is_rejected_not_silent(taxii_stub):
    _, base = taxii_stub
    _StubHandler.status = 200  # a 2xx, but not the canonical 202
    with pytest.raises(TaxiiError, match="expects 202"):
        push_bundle(BUNDLE, base, "coll1")


@pytest.mark.parametrize("code", [401, 403, 404, 500])
def test_push_bundle_http_errors_failclosed(taxii_stub, code):
    _, base = taxii_stub
    _StubHandler.status = code
    with pytest.raises(TaxiiError, match=f"HTTP {code}"):
        push_bundle(BUNDLE, base, "coll1")


def test_push_bundle_refuses_invalid_payload_before_network(taxii_stub):
    server, base = taxii_stub
    with pytest.raises(TaxiiError):
        push_bundle({"type": "bundle", "id": "bundle--x", "objects": []}, base, "coll1")
    assert server.requests == []  # nothing reached the wire


# ---------------------------------------------------------------------------
# CLI fail-closed policy
# ---------------------------------------------------------------------------

def test_cli_requires_https_url_without_allow_http(tmp_path, monkeypatch):
    src = tmp_path / "b.stix.json"
    src.write_text(json.dumps(BUNDLE), encoding="utf-8")
    for base in ("", "http://insecure.example.com/taxii2/"):
        monkeypatch.setenv(ENV_URL, base)
        result = subprocess.run(
            [sys.executable, str(TOOLS_DIR / "taxii_push.py"), "--file", str(src)],
            capture_output=True, text=True, timeout=60)
        assert result.returncode == 2
        assert "TAXII_PUSH_ERROR" in result.stderr


def test_cli_allow_http_refuses_nonloopback(tmp_path, monkeypatch):
    src = tmp_path / "b.stix.json"
    src.write_text(json.dumps(BUNDLE), encoding="utf-8")
    monkeypatch.setenv(ENV_URL, "http://10.0.0.5/taxii2/")
    result = subprocess.run(
        [sys.executable, str(TOOLS_DIR / "taxii_push.py"), "--file", str(src),
         "--allow-http"],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 2
    assert "loopback-only" in result.stderr


def test_cli_loopback_push_end_to_end(taxii_stub, tmp_path, monkeypatch):
    server, base = taxii_stub
    src = tmp_path / "b.stix.json"
    src.write_text(json.dumps(BUNDLE), encoding="utf-8")
    monkeypatch.setenv(ENV_URL, base)
    monkeypatch.setenv("AEGIS_TAXII_COLLECTION", "coll-loopback")
    result = subprocess.run(
        [sys.executable, str(TOOLS_DIR / "taxii_push.py"), "--file", str(src),
         "--allow-http"],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "status=202 objects=2" in result.stdout
    assert server.requests[0][0] == "/taxii2/collections/coll-loopback/objects/"


def test_cli_never_leaks_password_to_stderr(tmp_path, monkeypatch):
    src = tmp_path / "b.stix.json"
    src.write_text(json.dumps(BUNDLE), encoding="utf-8")
    monkeypatch.setenv(ENV_URL, "http://127.0.0.1:1/taxii2/")  # dead port
    monkeypatch.setenv("AEGIS_TAXII_USERNAME", "agent007")
    monkeypatch.setenv("AEGIS_TAXII_PASSWORD", "TOPSECRET")
    result = subprocess.run(
        [sys.executable, str(TOOLS_DIR / "taxii_push.py"), "--file", str(src),
         "--allow-http"],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 2
    assert "TOPSECRET" not in result.stderr
    assert "agent007" not in result.stderr


# ---------------------------------------------------------------------------
# Import hygiene: the module must not touch the host on import
# ---------------------------------------------------------------------------

def test_module_import_binds_nothing(monkeypatch):
    import importlib
    mod = importlib.import_module("taxii_push")
    assert mod.ENV_URL == "AEGIS_TAXII_URL"
    # The API above is the entire import surface; no server was started.
