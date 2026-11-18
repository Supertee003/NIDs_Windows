"""E6-BURST-001: an attack-shaped burst must never produce a host effect.

The stimulus is a burst of TCP connects across 150 loopback ports, i.e. a port
scan of localhost. Nothing leaves the host and nothing is sent to any remote
address.

**The scored half of this file is xfail, deliberately.** This install does not
capture loopback (`CAPTURE-LOOPBACK-001`), so a 127.0.0.1 scan cannot be shown
to reach the sensor, and the `forensic_records` / `packets_captured` /
`anomalies` deltas can be satisfied by ambient host traffic alone. The
2026-11-14 measurement quoted below recorded +52 ambient `anomalies` in the
same window, which is exactly why a raw delta is not an attribution. The
same stimulus class was proven at E5 on the Wi-Fi NIC instead: 40 SYNs produced
one R9006 row and 10 SYNs produced none
(`analysis/current-head/DETECT-L4-001-20261116.md`).

The marker is `strict=False` because the product is not what fails: the
assertion itself cannot attribute, so a red run must not accuse the detector.
An XPASS is also not evidence - on a busy host the three counters grow from
ambient traffic alone, which is exactly why the delta cannot be trusted. Read
the attributable sibling (`test_e6_l4_scan_detection.py`) for the claim, and
this marker as "measurement withdrawn, invariant kept".

What remains valid and unmarked is the safety invariant, measured on the
running product through its own CLI: the product **still performs no host
effect** - `blocks == 0`, `confirmed_blocks == 0`, `confirmed_quarantines == 0`,
no counter moves during the scan, and the PEP reports
`host_effect_capable: false`. AEGIS is detection-only; a scan must produce
evidence, never a block. That test is an invariant, not a detection proof.

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
@pytest.mark.xfail(
    strict=False,
    reason=(
        "CAPTURE-LOOPBACK-001: this test drives 127.0.0.1, which this install "
        "does not capture, so the burst cannot be shown to reach the sensor and "
        "the counter deltas are ambient-satisfiable (the 2026-11-14 run saw +52 "
        "ambient anomalies, and a 2026-11-17 run XPASSed on ambient growth alone). "
        "The stimulus class is proven at E5 on the Wi-Fi NIC "
        "instead (DETECT-L4-001: 40 ports -> one R9006 row, 10 -> none). "
        "Non-strict because the product is not what fails; a XPASS is ambient, "
        "not proof that loopback capture started working."
    ),
)
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
    """The detection-only invariant, asserted on the enforcement counters.

    This is not a detection proof: the loopback stimulus is not captured
    (`CAPTURE-LOOPBACK-001`), so a zero here means "no host effect was
    recorded", not "the scan reached the detector". Both are asserted: the
    counters must not move during the stimulus, and the absolute totals must
    stay zero for the life of the process.
    """
    before = _metrics()
    _scan()
    time.sleep(SETTLE_SECONDS)
    after = _metrics()

    for field in ("blocks", "confirmed_blocks", "confirmed_quarantines"):
        assert after[field] == before.get(field), (
            f"{field} moved from {before.get(field)} to {after[field]} during a scan; "
            "AEGIS is detection-only and must never act on the host"
        )
        assert after[field] == 0, (
            f"{field} is {after[field]}, not 0; the production build has a host "
            "effect and the detection-only claim is false"
        )

    health = _run("health", "--json")
    payload = json.loads(health.stdout[health.stdout.find("{"):])
    pep = payload.get("rust_pep") or {}
    assert pep.get("host_effect_capable") is False, (
        f"the PEP reports host_effect_capable={pep.get('host_effect_capable')}; "
        "the production build must not be able to enforce"
    )
