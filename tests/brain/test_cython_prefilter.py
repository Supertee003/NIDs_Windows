"""BRAIN-FASTPATH-FIX: Case-2 pre-filter detectors must never NameError.

brain/windows_brain.py's "Cython Fast-Path Pre-filter" block called
scan_nop_sled / scan_shellcode_markers / detect_repeated_byte, but no
definition or import of those names existed: the defining .pyx
(brain/cython/aegis_hotspot.pyx) was retired and never compiled, and the
replacement accelerator package (aegis_brain_cython) exported a different
API. With the compiled accelerator present (the production host ships
fast_scan.cp314-win_amd64.pyd), every Case-2 ("Forwarded: No Tier-1
Match") event raised NameError inside the main loop; the generic handler
counted an [ERROR] and the pure-Python regex scan was skipped -- Tier-2
went blind on exactly the forwarded events this pre-filter exists for.
With the module absent the block was skipped entirely, so the intended
detection never ran anywhere.

Unit pin: aegis_brain_cython.bridge now exports the three detectors with
the exact shapes the call sites consume (3-tuple / [(name, offset)] /
4-tuple). E2.

Behavioral pin: spawns the real brain (isolated alt port, scrubbed
secret, tmp cwd), sends a Case-2 datagram whose payload trips the
repeated-byte detector, and asserts the CYTHON-003 match reaches stdout
and anomalous.json with the old "name '...' is not defined" gone. E3.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "brain"))

from tests.runtime.conftest import component_output, start_component  # noqa: E402

# Absolute script path: the child runs with cwd=tmp_path (anomalous.json
# must not land in the repo), so a relative path would not resolve.
# -u: stdout is a pipe here, so CPython block-buffers it; the match print
# must be observable while the process is still running.
BRAIN = [sys.executable, "-u", str(REPO / "brain" / "windows_brain.py")]
# Same isolated alt-port band as the other brain loopback tests (EVT-177):
# the spawned brain never touches production :9999.
TEST_PORTS = (51996, 51995, 51994)


def _bridge():
    # Local import: the red state must fail per-test, not at collection.
    import aegis_brain_cython.bridge as bridge

    return bridge


# ---- scan_nop_sled: (found, longest_run, run_offset) ----

def test_nop_sled_finds_the_longest_run():
    bridge = _bridge()
    payload = b"\x41" * 10 + b"\x90" * 60 + b"\x42" * 5 + b"\x90" * 70
    assert bridge.scan_nop_sled(payload, 50) == (True, 70, 75)


def test_nop_sled_boundary_and_absence():
    bridge = _bridge()
    assert bridge.scan_nop_sled(b"\x90" * 50, 50) == (True, 50, 0)
    assert bridge.scan_nop_sled(b"\x90" * 49, 50) == (False, 49, 0)
    assert bridge.scan_nop_sled(b"\x41" * 100, 50) == (False, 0, 0)
    assert bridge.scan_nop_sled(b"", 50) == (False, 0, 0)


# ---- scan_shellcode_markers: [(marker_name, offset), ...] ----

def test_shellcode_markers_detect_each_known_marker():
    bridge = _bridge()
    assert bridge.scan_shellcode_markers(b"\x00\x0c\x0c\x0c\x0c\x00") == [("heap_spray_0c", 1)]
    assert bridge.scan_shellcode_markers(b"..meterpre..") == [("meterpreter", 2)]
    assert bridge.scan_shellcode_markers(b"\x00" + b"\xcc" * 8) == [("int3_padding", 1)]
    assert bridge.scan_shellcode_markers(b"\x41" * 32) == []
    assert bridge.scan_shellcode_markers(b"abc") == []


def test_shellcode_markers_report_heap_then_meterpreter_then_int3():
    bridge = _bridge()
    payload = b"\x0c" * 4 + b"meterpre" + b"\xcc" * 8
    assert bridge.scan_shellcode_markers(payload) == [
        ("heap_spray_0c", 0),
        ("meterpreter", 4),
        ("int3_padding", 12),
    ]


# ---- detect_repeated_byte: (found, byte, longest_run, offset) ----

def test_repeated_byte_finds_the_longest_run():
    bridge = _bridge()
    payload = b"\x41" * 10 + b"\x00" * 250 + b"\x42" * 5
    assert bridge.detect_repeated_byte(payload, 200) == (True, 0, 250, 10)


def test_repeated_byte_boundary_and_absence():
    bridge = _bridge()
    assert bridge.detect_repeated_byte(b"\xaa" * 200, 200) == (True, 0xAA, 200, 0)
    assert bridge.detect_repeated_byte(b"\xaa" * 199, 200) == (False, 0, 0, 0)
    assert bridge.detect_repeated_byte(b"", 200) == (False, 0, 0, 0)


# ---- behavioral: the real brain on an isolated port ----

def _free_udp_port() -> int | None:
    for port in TEST_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
    return None


def _health(port: int) -> dict:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3.0)
        sock.sendto(json.dumps({"op": "HEALTH"}).encode(), ("127.0.0.1", port))
        data, _ = sock.recvfrom(65535)
    return json.loads(data.decode("utf-8"))


def _send_raw(port: int, payload: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(payload, ("127.0.0.1", port))


def _wait_for(proc, needle: str, timeout: float = 15.0) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = "\n".join(component_output(proc)["stdout"])
        if needle in text:
            return text
        time.sleep(0.25)
    return "\n".join(component_output(proc)["stdout"])


def test_case2_event_reaches_the_prefilter_without_nameerror(tmp_path):
    port = _free_udp_port()
    if port is None:
        pytest.skip("no free loopback UDP port for the isolated brain")
    # logs/ under the tmp cwd keeps the brain's anomalous.json append out
    # of the repo tree (test hygiene: no writes to tracked tree state).
    (tmp_path / "logs").mkdir()
    child_env = dict(os.environ)
    child_env.pop("AEGIS_BRAIN_SECRET", None)
    proc = start_component(BRAIN + ["--port", str(port)], cwd=tmp_path, env=child_env)
    try:
        deadline = time.time() + 30
        started = False
        while True:
            try:
                if _health(port).get("state") == "RUNNING":
                    started = True
                    break
            except (OSError, ValueError):
                pass
            if time.time() > deadline:
                break
            time.sleep(0.5)
        if not started:
            tail = "\n".join(component_output(proc)["stdout"][-30:])
            raise AssertionError(f"brain never RUNNING:\n{tail}")

        event = {
            "source": "zig_pipeline",
            "src_ip": "10.0.0.66",
            "reason": "Forwarded: No Tier-1 Match",
            # 250 identical bytes trip detect_repeated_byte(run >= 200)
            # (CYTHON-003 heap-spray); no earlier marker exists in the payload.
            "raw_payload": "A" * 250,
        }
        _send_raw(port, json.dumps(event).encode("utf-8"))

        text = _wait_for(proc, "[CYTHON MATCH]")
        assert "[CYTHON MATCH]" in text, text
        assert "CYTHON-003" in text, text
        assert "Heap Spray Detected" in text, text
        # The pre-fix failure signature: no match print, the loop reported
        # `name 'scan_nop_sled' is not defined` instead.
        assert "is not defined" not in text, text

        anomaly = tmp_path / "logs" / "anomalous.json"
        assert anomaly.exists(), "detection never reached write_anomaly_log"
        record = json.loads(anomaly.read_text(encoding="utf-8").splitlines()[-1])
        assert record["rule_id"] == "CYTHON-003"
        assert record["attack_type"].startswith("Heap Spray Detected")
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=15)
