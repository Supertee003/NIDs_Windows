"""E6-BURST-001: an attack-shaped burst must be seen, scored, and never acted on.

`EVIDENCE_INDEX` had `E6_count: 0`: no gate ever put attack-shaped traffic in
front of the live pipeline. This one does, with a stimulus that is safe on a
working machine — a burst of TCP connects across 150 loopback ports, i.e. a port
scan of localhost. Nothing leaves the host and nothing is sent to any remote
address.

What it asserts, measured on the running product through its own CLI:

1. the evidence store grows (`forensic_records`) — the burst was captured;
2. the scoring path moves (`anomalies`) — the burst was evaluated, not just
   stored;
3. the product **still performs no host effect**: `blocks == 0`,
   `confirmed_blocks == 0`, `confirmed_quarantines == 0`, and the PEP reports
   `host_effect_capable: false`. AEGIS is detection-only; a scan must produce
   evidence, never a block.

Point 3 is the safety invariant, and it is the one that would fail loudly if the
product ever started enforcing. Point 2 uses a delta because the counter is a
rate-free total.

Measured before writing the assertions (2026-11-14, live host):
`detections +1, anomalies +52, forensic_records +4299, packets_captured +3171,
blocks +0, confirmed_blocks +0`.
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CTL = ROOT / "tools" / "aegisctl.py"

pytestmark = pytest.mark.host_live

SCAN_PORTS = 150
SETTLE_SECONDS = 5.0


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CTL), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=ROOT, timeout=120,
    )


def _metrics() -> dict:
    proc = _run("metrics")
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-1500:]
    return json.loads(proc.stdout[proc.stdout.find("{"):])


def _daemon_up() -> bool:
    return _run("status").returncode == 0


needs_daemon = pytest.mark.skipif(not _daemon_up(), reason="no running AEGIS daemon answers the CLI")


def _scan() -> None:
    for port in range(1, SCAN_PORTS + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.05)
        try:
            sock.connect(("127.0.0.1", port))
        except OSError:
            pass
        finally:
            sock.close()


@needs_daemon
def test_a_localhost_port_scan_is_captured_and_scored() -> None:
    before = _metrics()
    _scan()
    time.sleep(SETTLE_SECONDS)
    after = _metrics()

    assert after["forensic_records"] > before["forensic_records"], (
        "the burst produced no forensic evidence: "
        f"{before['forensic_records']} -> {after['forensic_records']}"
    )
    assert after["packets_captured"] > before["packets_captured"], (
        f"the burst was not captured: {before['packets_captured']} -> {after['packets_captured']}"
    )
    assert after["anomalies"] > before["anomalies"], (
        "the burst was stored but never scored: "
        f"anomalies {before['anomalies']} -> {after['anomalies']}"
    )


@needs_daemon
def test_a_scan_never_produces_a_host_effect() -> None:
    """The detection-only invariant, asserted on the enforcement counters."""
    before = _metrics()
    _scan()
    time.sleep(SETTLE_SECONDS)
    after = _metrics()

    for field in ("blocks", "confirmed_blocks", "confirmed_quarantines"):
        assert after[field] == 0, (
            f"{field} moved from {before.get(field)} to {after[field]} during a scan; "
            "AEGIS is detection-only and must never act on the host"
        )

    health = _run("health", "--json")
    payload = json.loads(health.stdout[health.stdout.find("{"):])
    pep = payload.get("rust_pep") or {}
    assert pep.get("host_effect_capable") is False, (
        f"the PEP reports host_effect_capable={pep.get('host_effect_capable')}; "
        "the production build must not be able to enforce"
    )
