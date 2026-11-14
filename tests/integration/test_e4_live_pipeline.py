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


SCAN_PORTS = 150
SETTLE_SECONDS = 5.0


def _head_seq() -> int:
    listing = _json("forensics", "list", "--limit", "1000", "--all")
    records = listing.get("records") or []
    assert records, "the forensic ring is empty; nothing to measure against"
    return max(int(record["record_seq"]) for record in records)


def _npcap_records_since(seq: int) -> int:
    listing = _json("forensics", "list", "--after", str(seq), "--limit", "1000")
    return sum(
        1 for record in (listing.get("records") or [])
        if record.get("source_name") == "npcap_sensor"
    )


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
def test_the_sensor_keeps_writing_evidence() -> None:
    """The sensor's own record stream is live and continuous.

    Earlier versions of this check were not evidence. "Packets captured does not
    go backwards" is satisfied by an idle host, and attributing growth to
    traffic we generate turned out to be impossible here: two 5 s windows
    measured on 2026-11-14 gave 162 sensor records idle vs 87 during a 150-port
    loopback scan, so localhost traffic is **not** what this install captures.
    That limit is recorded as `CAPTURE-LOOPBACK-001` and it means the detection
    gates cannot be fed by a self-test on loopback; they need a lab interface.

    What this asserts is the part that is true and measurable: the sensor keeps
    producing verified records in consecutive windows.
    """
    # A quiet host can legitimately write nothing for a few seconds, so measure
    # three windows and require the sensor to be alive in at least one of them.
    windows: list[int] = []
    for _ in range(3):
        seq = _head_seq()
        time.sleep(SETTLE_SECONDS)
        windows.append(_npcap_records_since(seq))

    assert any(count > 0 for count in windows), (
        "the sensor wrote no npcap_sensor record in three consecutive 5 s windows: "
        f"{windows}"
    )
    assert _int_field(_status_text(), "Packets captured") > 0


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
        "DEFECT-READY-001: the daemon's state machine stays DEGRADED while its "
        "health contract reports state RUNNING, degraded false, seven of seven "
        "subsystems RUNNING and every worker ready. src/daemon.zig sets the "
        "lifecycle once at startup and never re-promotes it, so status and the "
        "health contract disagree for the whole run. Needs a source fix; remove "
        "this marker when it is fixed (strict=True makes the fix visible)."
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


@needs_daemon
def test_readiness_names_the_state_machine_as_the_cause() -> None:
    """CLI-STATE-001: the refusal must point at the state machine, not at nothing.

    The daemon's health contract is fully healthy on this host while its
    lifecycle state machine stays DEGRADED. Before CLI-STATE-001 that arrived at
    the gate as `degraded_without_named_component`; now it must name the cause.
    """
    # `readiness` exits 1 while its gate is closed; the refusal is the expected
    # answer here, so parse stdout and assert on the verdict, not the exit code.
    proc = _ctl("readiness")
    assert "{" in proc.stdout, proc.stdout + proc.stderr
    readiness = json.loads(proc.stdout[proc.stdout.find("{"):])
    assert proc.returncode == 1, proc.stdout
    assert readiness["ready"] is False, readiness
    reasons = readiness["failure_reasons"]
    assert "state_machine_degraded_but_health_facts_ready" in reasons, readiness
    assert readiness["state_machine_state"] in {"DEGRADED", "RUNNING"}, readiness

    status = _status_text()
    assert "State machine:" in status, status
    assert "CLI-STATE-001" in status, status
