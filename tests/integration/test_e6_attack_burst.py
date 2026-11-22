"""E6-BURST-001: an attributable loopback burst is scored, with no host effect.

The stimulus is a 40-port TCP SYN burst from a dedicated loopback source
(127.0.0.2) to 127.0.0.1. Nothing leaves the host.

The old scored half was marked xfail because raw `forensic_records` /
`packets_captured` / `anomalies` deltas are ambient-satisfiable (the 2026-11-14
window recorded +52 ambient anomalies, and a 2026-11-17 run XPASSed on ambient
growth alone). That marker is gone: the burst is now attributed with the exact
5-tuple in the core NDJSON log and a below-threshold negative control, the same
standard as `test_e6_l4_scan_detection.py`. An ambient counter cannot pass it.

The safety invariant remains independent and unmarked: the product performs no
host effect - `blocks`, `confirmed_blocks`, `confirmed_quarantines` stay zero
and the PEP reports `host_effect_capable: false`. AEGIS is detection-only; a
scan must produce evidence, never a block.
"""
from __future__ import annotations

import json
import time

import pytest

from loopback_attribution import (
    NEGATIVE_PORTS,
    NEGATIVE_SRC,
    POSITIVE_PORTS,
    POSITIVE_SRC,
    RATE_WINDOW_SECONDS,
    SETTLE_SECONDS,
    ctl,
    ctl_json,
    event_log_path,
    log_offset,
    npcap_pushed,
    r9006_hits,
    rows_since,
    scan,
)

pytestmark = pytest.mark.host_live


def _daemon_up() -> bool:
    return ctl("status").returncode == 0


needs_daemon = pytest.mark.skipif(not _daemon_up(), reason="no running AEGIS daemon answers the CLI")


@needs_daemon
def test_a_localhost_port_scan_is_captured_and_scored() -> None:
    """The burst is captured, scored and attributed - not merely counted."""
    before = ctl_json("metrics")
    log = event_log_path()
    offset = log_offset(log)
    ingress_before = npcap_pushed()

    sports, _ = scan(POSITIVE_SRC, 24000, POSITIVE_PORTS)
    assert len(sports) == POSITIVE_PORTS, "the burst did not bind its source sockets"
    time.sleep(SETTLE_SECONDS)

    after = ctl_json("metrics")
    ingress_after = npcap_pushed()
    rows = rows_since(log, offset)
    hits = r9006_hits(rows, POSITIVE_SRC, sports)

    assert ingress_after > ingress_before, (
        f"loopback burst was not captured: capture_npcap.pushed "
        f"{ingress_before} -> {ingress_after}"
    )
    assert after["forensic_records"] > before["forensic_records"], (
        "the burst produced no forensic evidence: "
        f"{before['forensic_records']} -> {after['forensic_records']}"
    )
    assert after["packets_captured"] > before["packets_captured"], (
        f"the burst was not counted as captured: {before['packets_captured']} -> {after['packets_captured']}"
    )
    assert after["anomalies"] > before["anomalies"], (
        "the burst was stored but never scored: "
        f"anomalies {before['anomalies']} -> {after['anomalies']}"
    )
    assert hits, (
        f"no R9006 row attributed to {POSITIVE_SRC} / test-owned ports; "
        f"only {len(rows)} new log rows were written - counters alone are not proof"
    )
    assert hits[0].get("host_effect_confirmed") is False

    # Below-threshold control from a different source: no attributable R9006 row.
    time.sleep(RATE_WINDOW_SECONDS)
    neg_offset = log_offset(log)
    neg_sports, _ = scan(NEGATIVE_SRC, 24100, NEGATIVE_PORTS)
    assert len(neg_sports) == NEGATIVE_PORTS, "the control did not bind its source sockets"
    time.sleep(SETTLE_SECONDS)
    neg_hits = r9006_hits(rows_since(log, neg_offset), NEGATIVE_SRC, neg_sports)
    assert not neg_hits, (
        f"R9006 fired for the {NEGATIVE_PORTS}-port control from {NEGATIVE_SRC}"
    )


@needs_daemon
def test_a_scan_never_produces_a_host_effect() -> None:
    """Detection-only invariant, asserted on the enforcement counters.

    This is not a detection proof; it checks that the stimulus never moves a
    host-effect counter and that the absolute totals stay zero for the life of
    the process.
    """
    before = ctl_json("metrics")
    sports, _ = scan(POSITIVE_SRC, 24000, POSITIVE_PORTS)
    assert len(sports) == POSITIVE_PORTS
    time.sleep(SETTLE_SECONDS)
    after = ctl_json("metrics")

    for field in ("blocks", "confirmed_blocks", "confirmed_quarantines"):
        assert after[field] == before.get(field), (
            f"{field} moved from {before.get(field)} to {after[field]} during a scan; "
            "AEGIS is detection-only and must never act on the host"
        )
        assert after[field] == 0, (
            f"{field} is {after[field]}, not 0; the production build has a host "
            "effect and the detection-only claim is false"
        )

    health = ctl("health", "--json")
    payload = json.loads(health.stdout[health.stdout.find("{"):])
    pep = payload.get("rust_pep") or {}
    assert pep.get("host_effect_capable") is False, (
        f"the PEP reports host_effect_capable={pep.get('host_effect_capable')}; "
        "the production build must not be able to enforce"
    )
