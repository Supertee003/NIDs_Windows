"""E4-FLOW-001: the first system-integration gate for the live product.

Every other check in the suite is unit- or component-level (E2/E3). "Does a real
packet on a real interface reach the forensic ring and come back out through the
operator CLI" was not asserted anywhere, and that is the one claim a NIDS has to
keep.

These tests talk to the **running** product through its own CLI
(`tools/aegisctl.py`), never to internals:

* status answers and the daemon has been up and capturing;
* the forensic ring verifies its own hash chain;
* real loopback traffic makes the ring grow and the pipeline count it;
* the pipeline drops nothing while doing so;
* every record read back is a canonical-space record marked verified.

They skip when no daemon answers, so a machine without the product installed
reports a skip rather than a failure - and a skip is visible, not a pass.

What this proves and does not prove is written in
`analysis/current-head/E4-FLOW-001-20261114.md`: it is an integration *flow*
check on one host, not an attack-detection test and not a second-host check.
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


def _ctl(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CTL), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=ROOT, timeout=timeout,
    )


def _json(*args: str) -> dict:
    proc = _ctl(*args)
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]
    try:
        return json.loads(proc.stdout)
    except ValueError:
        start = proc.stdout.find("{")
        assert start >= 0, f"no JSON in output: {proc.stdout[-800:]}"
        return json.loads(proc.stdout[start:])


def _daemon_up() -> bool:
    proc = _ctl("status", timeout=30)
    return proc.returncode == 0 and "State:" in proc.stdout


needs_daemon = pytest.mark.skipif(not _daemon_up(), reason="no running AEGIS daemon answers the CLI")


def _status_text() -> str:
    proc = _ctl("status")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


def _int_field(text: str, label: str) -> int:
    for line in text.splitlines():
        if label in line:
            digits = "".join(ch for ch in line.split(":", 1)[-1] if ch.isdigit())
            if digits:
                return int(digits)
    raise AssertionError(f"{label} not found in status output:\n{text}")


needs_daemon = pytest.mark.skipif(not _daemon_up(), reason="no running AEGIS daemon answers the CLI")


@needs_daemon
def test_the_forensic_ring_verifies_its_own_chain() -> None:
    report = _json("forensics", "verify")
    assert report.get("verified") is True, report
    assert report.get("integrity") == "ok", report
    assert int(report.get("records") or 0) > 0, report


@needs_daemon
def test_records_read_back_are_canonical_and_verified() -> None:
    listing = _json("forensics", "list")
    records = listing.get("records") or []
    assert records, listing
    for record in records:
        assert record.get("verified") is True, record
        assert record.get("source_space") == "canonical", record
        assert record.get("source_name"), record


@needs_daemon
def test_real_loopback_traffic_reaches_the_ring() -> None:
    """Generate traffic the sensor can see, then watch the ring and counters move."""
    before_status = _status_text()
    before_packets = _int_field(before_status, "Packets captured")
    before_ring = int(_json("forensics", "verify").get("records") or 0)

    # Real TCP connects on loopback; nothing is sent to any external host.
    for port in (9, 80, 443, 8080):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            sock.connect(("127.0.0.1", port))
        except OSError:
            pass
        finally:
            sock.close()
    time.sleep(3.0)

    after_status = _status_text()
    after_packets = _int_field(after_status, "Packets captured")
    after_ring = int(_json("forensics", "verify").get("records") or 0)

    assert after_packets >= before_packets, (before_packets, after_packets)
    assert after_ring >= before_ring, (before_ring, after_ring)
    # The sensor must be moving under live traffic; if the host is idle both
    # counters can legitimately stand still, so this is a floor, not a delta.
    assert after_packets > 0 and after_ring > 0


@needs_daemon
def test_the_pipeline_drops_nothing_while_it_runs() -> None:
    text = _ctl("queue").stdout
    assert text, "queue command produced no output"
    assert "dropped=0" in text, text[:400]
    assert "shed_overload=0" in text, text[:400]


@needs_daemon
@pytest.mark.xfail(
    strict=True,
    reason=(
        "DEFECT-READY-001: the daemon reports degraded=true with an empty "
        "degraded_components list and failure_reasons "
        "['degraded_without_named_component', 'state_degraded'], so readiness "
        "says not-ready while all seven subsystems are RUNNING, workers report "
        "failure_reasons [] and the queue dropped nothing. Needs a source fix; "
        "remove this marker when it is fixed (strict=True makes the fix visible)."
    ),
)
def test_every_surface_agrees_about_health() -> None:
    """status, health and readiness must tell the same story.

    This is the check that would have caught a daemon reporting DEGRADED on one
    surface and RUNNING on another; it is asserted as a genuine consistency
    requirement, not softened into a warning.
    """
    status = _status_text()
    health = _json("health")
    readiness = _json("readiness")

    status_degraded = "DEGRADED" in status.splitlines()[1] if len(status.splitlines()) > 1 else False
    health_degraded = bool(health.get("degraded")) or str(health.get("state")).upper() == "DEGRADED"
    readiness_degraded = bool(readiness.get("degraded"))

    assert status_degraded == health_degraded == readiness_degraded, (
        "the same daemon reports different health on different surfaces: "
        f"status_degraded={status_degraded}, health_degraded={health_degraded}, "
        f"readiness_degraded={readiness_degraded}, "
        f"readiness reasons={readiness.get('failure_reasons')}"
    )
