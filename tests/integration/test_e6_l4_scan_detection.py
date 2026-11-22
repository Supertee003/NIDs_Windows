"""A loopback SYN scan reaches the sensor and fires the L4 rate rule.

`configs/Rules.json` ships R9006 as a real rate rule (`FLAGS:S`,
`rate_mode: distinct_dst_ports`, `rate_threshold: 20`, `rate_window_ms: 10000`).
`src/pipeline/event_processor.zig` evaluates it when `ev.source ==
.capture_npcap`, and canonical Nose frames map to exactly that source.

`DETECT-L4-001` closed the rule path on the Wi-Fi NIC on 2026-11-16 (40 SYNs ->
one R9006 row, 10 -> none). The loopback half stayed xfail because a raw delta
could not attribute a row to the scan: CAPTURE-LOOPBACK-001 was a *binding*
gap, not a missing Npcap feature. With the sensor pinned to
`\\Device\\NPF_Loopback` the full path is now provable, and this test asserts
it with an exact 5-tuple instead of an ambient-satisfiable counter delta:

    Nose full capture -> pipe -> Zig queue -> R9006 -> core NDJSON row

The burst uses a dedicated source (127.0.0.2) and requires the R9006 row to
name that IP *and* an ephemeral source port owned by the test sockets. A
10-port control from 127.0.0.3 must produce no such row. The canonical ingress
counter must advance across the burst.

Nothing here is about enforcement: AEGIS is detection-only, so a rule hit only
raises a record and a counter, and the hit row must carry
`host_effect_confirmed: false`.
"""
from __future__ import annotations

import socket
import time

import pytest

from loopback_attribution import (
    LOOPBACK_DST,
    NEGATIVE_PORTS,
    NEGATIVE_SRC,
    POSITIVE_PORTS,
    POSITIVE_SRC,
    RATE_WINDOW_SECONDS,
    SETTLE_SECONDS,
    ctl_json,
    ctl,
    event_log_path,
    log_offset,
    npcap_pushed,
    r9006_hits,
    rows_since,
    scan,
)

pytestmark = pytest.mark.host_live

SETTLE_SECONDS_RING = 6.0


def _daemon_up() -> bool:
    return ctl("status").returncode == 0


needs_daemon = pytest.mark.skipif(not _daemon_up(), reason="no running AEGIS daemon answers the CLI")


@needs_daemon
def test_the_ring_keeps_accepting_records_before_asking_about_detection() -> None:
    """Precondition: the evidence path is writing at all.

    Measured on the counter, not on a record cursor: with roughly 700 records/s
    the ring keeps only about 23 s of history, and `--after` a cursor that has
    already rotated out returns nothing even though the daemon is healthy. That
    is a measurement artefact, not a stall (it made an earlier version of this
    guard fail spuriously).
    """
    before = int(ctl_json("metrics").get("forensic_records") or 0)
    time.sleep(SETTLE_SECONDS_RING)
    after = int(ctl_json("metrics").get("forensic_records") or 0)
    assert after > before, f"nothing was written in {SETTLE_SECONDS_RING}s: {before} -> {after}"


@needs_daemon
def test_a_syn_scan_is_tagged_by_an_l4_rule() -> None:
    """Attributable R9006 hit on loopback plus a below-threshold negative control.

    The old version counted any `npcap_sensor` row in a window, which could not
    exclude ambient traffic and was therefore marked xfail. Here the claim is
    tied to the exact source IP and the exact ephemeral ports the test sockets
    bound, so an ambient row cannot satisfy it.
    """
    log = event_log_path()
    offset = log_offset(log)
    ingress_before = npcap_pushed()

    sports, dst_ports = scan(POSITIVE_SRC, 24000, POSITIVE_PORTS)
    assert sports and len(dst_ports) == POSITIVE_PORTS, "the positive scan did not bind its source sockets"
    time.sleep(SETTLE_SECONDS)

    ingress_after = npcap_pushed()
    positive_rows = rows_since(log, offset)
    hits = r9006_hits(positive_rows, POSITIVE_SRC, sports)

    assert ingress_after > ingress_before, (
        "canonical ingress did not advance during the loopback burst "
        f"(capture_npcap.pushed {ingress_before} -> {ingress_after}); "
        "the sensor is not bound to the loopback interface"
    )
    assert hits, (
        f"no R9006 row attributed to {POSITIVE_SRC} / test-owned ports "
        f"{min(sports)}..{max(sports)} in {len(positive_rows)} new log rows; "
        "loopback capture or the L4 rule path is broken"
    )

    hit = hits[0]
    assert hit.get("host_effect_confirmed") is False, (
        "the R9006 hit reports a host effect; AEGIS is detection-only"
    )

    # Negative control: same sensor, below the 20-distinct-port threshold, from
    # a different loopback source. R9006 must not fire for it.
    time.sleep(RATE_WINDOW_SECONDS)
    neg_offset = log_offset(log)
    neg_sports, neg_dst = scan(NEGATIVE_SRC, 24100, NEGATIVE_PORTS)
    assert neg_sports and len(neg_dst) == NEGATIVE_PORTS, "the negative scan did not bind its source sockets"
    time.sleep(SETTLE_SECONDS)

    neg_rows = rows_since(log, neg_offset)
    neg_hits = r9006_hits(neg_rows, NEGATIVE_SRC, neg_sports)
    assert not neg_hits, (
        f"R9006 fired for a {NEGATIVE_PORTS}-port control from {NEGATIVE_SRC}; "
        "the distinct-dst-ports threshold is not being enforced"
    )

    # Guard against a stimulus that could not possibly reach the loopback sensor.
    assert dst_ports[0] == 24000 and dst_ports[-1] == 24000 + POSITIVE_PORTS - 1
    assert LOOPBACK_DST == "127.0.0.1"
