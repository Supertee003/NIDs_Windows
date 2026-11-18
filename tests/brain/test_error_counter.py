"""B2-ERRCNT-053: brain HEALTH errors counter is live (behavioral).

The HEALTH probe reports in/out/errors/dropped, but no code path ever
incremented ERROR_COUNT — supervisors saw eternal zero. Internal loop
failures (anything past JSON parsing) now count. Spawns the real brain
as a subprocess against 127.0.0.1:9999, sends a valid-JSON non-dict
datagram (deterministic AttributeError past the parse stage), and
asserts errors+1 with in_events unchanged. E4-local (live loopback).

Process handling uses tests.runtime.conftest.start_component (drain
threads): a PIPE nobody reads fills up during the banner burst and the
brain stalls before binding — the harness documents this exact artifact.
"""
from __future__ import annotations

import json
import socket
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from tests.runtime.conftest import component_output, start_component  # noqa: E402

BRAIN = [sys.executable, "brain/windows_brain.py"]
UDP = ("127.0.0.1", 9999)

# Isolated-test ports: a spawned brain binds here instead of :9999 so
# the suite never touches the production brain (EVT-177). The daemon
# keeps sending to :9999; the alt port receives only direct test
# traffic. Secret is scrubbed for the child (bare wire accepted per
# the legacy matrix row), so results are identical on hosts with and
# without AEGIS_BRAIN_SECRET provisioned.
TEST_PORTS = (51999, 51998, 51997)


def _free_udp_port() -> int | None:
    for port in TEST_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
    return None


def health(port: int) -> dict:
    # Fresh socket per probe: on Windows, early probes sent while the brain
    # is still starting elicit ICMP port-unreachable, which poisons later
    # recvfrom calls on the SAME socket with ConnectionResetError long
    # after the brain is up. A new socket per probe sidesteps the quirk.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3.0)
        sock.sendto(json.dumps({"op": "HEALTH"}).encode(), ("127.0.0.1", port))
        data, _ = sock.recvfrom(65535)
    return json.loads(data.decode("utf-8"))


def send_raw(port: int, payload: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(payload, ("127.0.0.1", port))


def test_internal_failure_increments_errors_counter():
    # Isolated brain on an alt port: the suite never touches the
    # production brain. Env scrubbed for the child (bare wire accepted
    # per the legacy matrix row), so results are identical on hosts
    # with and without AEGIS_BRAIN_SECRET provisioned.
    import os
    port = _free_udp_port()
    if port is None:
        pytest.skip("no free loopback UDP port for the isolated brain")
    child_env = dict(os.environ)
    child_env.pop("AEGIS_BRAIN_SECRET", None)
    proc = start_component(BRAIN + ["--port", str(port)], cwd=REPO, env=child_env)
    try:
        deadline = time.time() + 30
        started_ok = False
        while True:
            try:
                if health(port).get("state") == "RUNNING":
                    started_ok = True
                    break
            except (OSError, ValueError):
                pass
            if time.time() > deadline:
                break
            time.sleep(0.5)
        if not started_ok:
            tail = "\n".join(component_output(proc)["stdout"][-30:])
            raise AssertionError(f"brain never RUNNING:\n{tail}")
        before = health(port)
        e0, i0 = before["counters"]["errors"], before["counters"]["in_events"]
        send_raw(port, b"[1,2]")  # valid JSON, non-dict: dies past parse
        time.sleep(3.0)
        after = health(port)
        assert after["counters"]["errors"] == e0 + 1, after["counters"]
        assert after["counters"]["in_events"] == i0, after["counters"]
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=15)
