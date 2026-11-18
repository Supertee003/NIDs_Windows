"""The loopback SYN scan cannot reach the sensor; the rule path itself is proven.

`configs/Rules.json` ships three L4 rules and R9006 is a real rate rule
(`rate_mode: distinct_dst_ports`, `rate_threshold: 20`, `rate_window_ms: 10000`).
`src/pipeline/event_processor.zig:307` evaluates them when
`ev.source == .capture_npcap`, and canonical nose frames map to exactly that
source, so the code path exists for production traffic.

`DETECT-L4-001` was closed on 2026-11-16 on that canonical path, not here: a
40-port SYN burst from this host over the Wi-Fi NIC produced one R9006 row and a
10-port control produced none
(`admin-evidence/lab-l4-testnet-20261116/`,
`admin-evidence/lab-l4-testnet-negative-20261116/`, and
`analysis/current-head/DETECT-L4-001-20261116.md`).

This test still drives `127.0.0.1`, which this install does not capture
(`CAPTURE-LOOPBACK-001`), so it remains xfail for a *stimulus* reason: an xfail
here does not say the rule path is broken. It stays as the tripwire for the day
someone points it at a captured interface - a pass would mean the loopback limit
is gone. `strict=False` on purpose: both outcomes are informative.

Nothing here is about enforcement: AEGIS is detection-only, and a rule hit would
only raise a record and a counter.
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
SETTLE_SECONDS = 6.0


def _ctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CTL), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=ROOT, timeout=120,
    )


def _json(*args: str) -> dict:
    proc = _ctl(*args)
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-1500:]
    return json.loads(proc.stdout[proc.stdout.find("{"):])


def _daemon_up() -> bool:
    return _ctl("status").returncode == 0


needs_daemon = pytest.mark.skipif(not _daemon_up(), reason="no running AEGIS daemon answers the CLI")


def _head_seq() -> int:
    records = _json("forensics", "list", "--limit", "1000", "--all").get("records") or []
    assert records
    return max(int(record["record_seq"]) for record in records)


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
def test_the_ring_keeps_accepting_records_before_asking_about_detection() -> None:
    """Precondition for the scan verdict: the evidence path is writing at all.

    Measured on the counter, not on a record cursor: with roughly 700 records/s
    the ring keeps only about 23 s of history, and `--after` a cursor that has
    already rotated out returns nothing even though the daemon is healthy. That
    is a measurement artefact, not a stall (it made an earlier version of this
    guard fail spuriously).
    """
    before = int(_json("metrics").get("forensic_records") or 0)
    time.sleep(SETTLE_SECONDS)
    after = int(_json("metrics").get("forensic_records") or 0)
    assert after > before, f"nothing was written in {SETTLE_SECONDS}s: {before} -> {after}"


@needs_daemon
@pytest.mark.xfail(
    strict=False,
    reason=(
        "CAPTURE-LOOPBACK-001: this test drives 127.0.0.1, which this install "
        "does not capture, so the scan cannot be shown to reach the sensor. The "
        "rule path itself was proven on the Wi-Fi NIC on 2026-11-16 "
        "(DETECT-L4-001 closed: 40 ports -> one R9006 row, 10 ports -> none). "
        "Non-strict on purpose: an XPASS would mean loopback capture started "
        "working, which is worth seeing."
    ),
)
def test_a_syn_scan_is_tagged_by_an_l4_rule() -> None:
    """Only **sensor** records count: a tagged file or registry record is not the scan.

    The first version counted any tagged record in the window, which produced two
    XPASSes that could not be attributed to the scan — the daemon also tags file
    and registry telemetry (R1001-style rules). Attribution is part of the claim,
    so only `npcap_sensor` records are counted here.
    """
    rounds: list[int] = []
    sensor_tagged = 0
    other_tagged = 0
    for _ in range(3):
        before = int(_json("metrics").get("detections") or 0)
        _scan()
        time.sleep(SETTLE_SECONDS)
        rounds.append(int(_json("metrics").get("detections") or 0) - before)
        seq = _head_seq()
        records = _json("forensics", "list", "--after", str(seq), "--limit", "1000").get("records") or []
        for record in records:
            if int(record.get("rule_id") or 0) == 0:
                continue
            if record.get("source_name") == "npcap_sensor":
                sensor_tagged += 1
            else:
                other_tagged += 1
    assert sensor_tagged > 0, (
        "no sensor record was rule-tagged in three scan rounds "
        f"(detections deltas {rounds}, tagged non-sensor records {other_tagged})"
    )
