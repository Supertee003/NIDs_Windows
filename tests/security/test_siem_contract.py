"""SIEM-CFG-033: siem_config.json claims match the forwarder (static contract).

configs/siem_config.json once marked http/https/tcp/udp as "Not yet
implemented" while src/forensic/siem_forwarder.zig implements all five
transports (batch + spool-replay paths) and all three formats. A stale
"not implemented" note sends operators down a dead end, so this pins the
parity both ways: no transport may carry a not-implemented note, and every
transport/format named by the config must have a real send/format path in
the forwarder source. No daemon needed. E1 (static) + E2 (config parse).
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / "configs" / "siem_config.json"
FORWARDER = REPO / "src" / "forensic" / "siem_forwarder.zig"

# config transport -> (batch sender, spool-replay sender) in forwarder source
TRANSPORT_PATHS = {
    "file": ("sendToFile", "sendRawToFile"),
    "http": ("sendViaHttp", "sendRawViaHttp"),
    "https": ("sendViaHttp", "sendRawViaHttp"),
    "tcp": ("sendViaTcp", "sendRawViaTcp"),
    "udp": ("sendViaUdp", "sendRawViaUdp"),
}

FORMAT_PATHS = {
    "ndjson": "formatAsNdjson",
    "cef": "formatAsCef",
    "syslog": "formatAsSyslog",
}


def load_config() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def test_config_lists_all_transports_and_formats():
    doc = load_config()
    assert set(doc["transports"]) == set(TRANSPORT_PATHS)
    assert set(doc["formats"]) == set(FORMAT_PATHS)


def test_no_transport_claims_not_implemented():
    doc = load_config()
    stale = [
        name for name, spec in doc["transports"].items()
        if "not yet implemented" in json.dumps(spec).lower()
        or "not implemented" in json.dumps(spec).lower()
    ]
    assert stale == [], f"transports with stale not-implemented notes: {stale}"


def test_every_transport_has_batch_and_replay_path():
    src = FORWARDER.read_text(encoding="utf-8")
    for transport, (batch_fn, replay_fn) in TRANSPORT_PATHS.items():
        assert f"fn {batch_fn}(" in src, f"missing batch sender for {transport}"
        assert f"fn {replay_fn}(" in src, f"missing spool-replay sender for {transport}"


def test_every_format_has_formatter():
    src = FORWARDER.read_text(encoding="utf-8")
    for fmt, fn in FORMAT_PATHS.items():
        assert f"fn {fn}(" in src, f"missing formatter for {fmt}"


def test_default_forwarder_block_is_internally_consistent():
    doc = load_config()["siem_forwarder"]
    assert doc["transport"] in TRANSPORT_PATHS, doc["transport"]
    assert doc["format"] in FORMAT_PATHS, doc["format"]
    assert isinstance(doc["batch_size"], int) and doc["batch_size"] > 0
    assert isinstance(doc["retry_count"], int) and doc["retry_count"] >= 0
