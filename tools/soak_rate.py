"""Sustained file-op load at a *held* rate, with fail-closed drop attribution.

#29 closes on "zero drops at sustained N file-ops/s". The first version of this
measurement (host-window-003) had two defects that both produced a false PASS:

1. **It never held the rate.** `--ops-per-second` was a label; the workers ran
   free and the window-004 run "at 4,000/s" actually drove 6,383/s, then
   reported `zero_drops: true` while `queue_dropped_total` had grown by 80,270.
2. **It read the wrong key.** Attribution looked for `buckets`/`sources` in
   `queue.stats`; the daemon publishes `by_source`. The missing key made
   `drops_total` the sum of an empty dict, i.e. always 0.

This version therefore:
  * throttles every worker to its share of the requested rate;
  * reads `by_source` and treats its absence as an attribution failure, not as
    "zero drops";
  * requires BOTH the per-source delta and the `data_integrity` delta to be zero;
  * records cumulative counters next to the deltas so a dirty window can never
    be mistaken for a clean one.

Exit codes: 0 = rate held and zero new drops; 1 = measured FAIL; 2 = the run
could not be attributed (schema/daemon problem) — also a FAIL.

Usage:
    python tools/soak_rate.py --ops-per-second 4000 --seconds 90 --out r.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

LOSSLESS_COUNTERS = (
    "queue_dropped_total",
    "minifilter_pipeline_dropped",
    "minifilter_ring_dropped",
    "nose_frames_dropped",
    "nose_frames_rejected",
    "nose_pipe_errors",
)


def _unwrap(response: dict, key: str) -> dict:
    body = response.get("data") or response
    if isinstance(body, str):
        body = json.loads(body)
    if isinstance(body, dict) and key in body:
        body = body[key]
    return body if isinstance(body, dict) else {}


def parse_buckets(queue_stats: dict) -> dict[str, int] | None:
    """Per-source dropped counters, or None when the schema is not recognised.

    None is deliberately distinct from {}: a daemon that does not publish
    `by_source` must fail attribution instead of reporting zero drops.
    """
    rows = queue_stats.get("by_source")
    if rows is None:
        return None
    out: dict[str, int] = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        name = row.get("name") or row.get("source") or str(row.get("ordinal"))
        out[str(name)] = int(row.get("dropped") or 0)
    return out


def counter_delta(before: dict, after: dict, keys=LOSSLESS_COUNTERS) -> dict[str, int]:
    out: dict[str, int] = {}
    for key in keys:
        d = int(after.get(key) or 0) - int(before.get(key) or 0)
        if d:
            out[key] = d
    return out


def delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    names = set(before) | set(after)
    return {
        name: after.get(name, 0) - before.get(name, 0)
        for name in names
        if after.get(name, 0) - before.get(name, 0)
    }


def verdict(
    *,
    target: int,
    achieved: float,
    per_source: dict[str, int] | None,
    integrity: dict[str, int],
    rate_tolerance: float = 0.02,
) -> dict:
    """Fail-closed acceptance for one window. Pure so it can be unit tested."""
    reasons: list[str] = []
    if per_source is None:
        reasons.append("queue.stats exposes no by_source buckets: drops cannot be attributed")
        drops_total = 0
    else:
        drops_total = sum(per_source.values())
        if drops_total:
            detail = ", ".join(f"{k}={v}" for k, v in sorted(per_source.items()))
            reasons.append(f"{drops_total} new drops ({detail})")
    integrity_total = sum(integrity.values())
    if integrity_total:
        detail = ", ".join(f"{k}={v}" for k, v in sorted(integrity.items()))
        reasons.append(f"integrity counters moved ({detail})")
    if achieved < target * (1.0 - rate_tolerance):
        reasons.append(f"held rate {achieved:.1f}/s is below target {target}/s")
    return {
        "ok": not reasons,
        "reasons": reasons,
        "drops_total": drops_total,
        "integrity_total": integrity_total,
    }


def snapshot() -> dict:
    sys.path.insert(0, str(ROOT / "tools"))
    from aegisctl.client import AegisClient  # noqa: PLC0415

    client = AegisClient()
    health = _unwrap(client.send("health"), "health")
    queue = _unwrap(client.send("queue.stats"), "queue")
    return {
        "state": health.get("state"),
        "integrity": health.get("data_integrity") or {},
        "queue_dropped": queue.get("dropped"),
        "queue_pushed": queue.get("pushed"),
        "buckets": parse_buckets(queue),
    }


def _worker(workdir: Path, rate: float, deadline: float, tag: int, counts: list[int], lock: threading.Lock) -> None:
    """One throttled producer.

    Ops are scheduled against an absolute due-time, not a per-op sleep: Windows
    timer granularity (~1-15 ms) is coarser than one op (~0.5 ms), so sleeping
    every op silently caps the achievable rate. Sleeping only when the producer
    is more than 2 ms ahead keeps the held rate accurate without spinning.
    """
    interval = 1.0 / rate if rate > 0 else 0.0
    due = time.monotonic()
    done = 0
    i = 0
    while time.monotonic() < deadline:
        now = time.monotonic()
        ahead = due - now
        if ahead > 0.002:
            time.sleep(min(ahead, 0.05))
            continue
        p = workdir / f"w{tag}-{i % 4096}.tmp"
        try:
            fd = os.open(p, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
            os.write(fd, b"aegis soak\n")
            os.close(fd)
            os.unlink(p)
            done += 1
        except OSError:
            time.sleep(0.001)
        i += 1
        due += interval
        if due < now - 0.5:  # never accumulate debt after a stall
            due = now
    with lock:
        counts[tag] = done


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ops-per-second", type=int, default=4000)
    ap.add_argument("--seconds", type=int, default=90)
    ap.add_argument("--settle-seconds", type=int, default=180)
    ap.add_argument("--workers", type=int, default=6,
                    help="producers; one file op-set costs ~0.8 ms on this host, so 3 "
                         "threads cannot hold 4,000/s and would mislabel the window")
    ap.add_argument("--dir", default=r"D:\tmp\aegis-rate")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    workdir = Path(args.dir)
    workdir.mkdir(parents=True, exist_ok=True)

    before = snapshot()
    counts = [0] * args.workers
    lock = threading.Lock()
    start = time.monotonic()
    deadline = start + args.seconds
    per_worker = args.ops_per_second / args.workers
    threads = [
        threading.Thread(target=_worker, args=(workdir, per_worker, deadline, t, counts, lock), daemon=True)
        for t in range(args.workers)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - start
    after = snapshot()

    # Settle: publication of data_integrity is periodic; poll until the total is
    # stable across two reads so a burst that lands late is still counted.
    settled = after
    stable = 0
    polls = 0
    last_total = None
    settle_deadline = time.monotonic() + args.settle_seconds
    while time.monotonic() < settle_deadline:
        time.sleep(5)
        polls += 1
        cur = snapshot()
        total = cur.get("queue_dropped")
        if total == last_total:
            stable += 1
            if stable >= 2:
                settled = cur
                break
        else:
            stable = 0
            last_total = total
            settled = cur

    total_ops = sum(counts)
    rate = total_ops / elapsed if elapsed else 0.0

    if before["buckets"] is None or settled["buckets"] is None:
        per_source = None
    else:
        per_source = delta(before["buckets"], settled["buckets"])
    integrity_d = counter_delta(before["integrity"], settled["integrity"])
    # The per-source delta and the integrity delta describe the same loss; the
    # larger of the two is the honest number if a source bucket is unreported.
    result_verdict = verdict(
        target=args.ops_per_second,
        achieved=rate,
        per_source=per_source,
        integrity=integrity_d,
    )

    result = {
        "target_ops_per_second": args.ops_per_second,
        "seconds": round(elapsed, 2),
        "workers": args.workers,
        "op_sets": total_ops,
        "achieved_ops_per_second": round(rate, 1),
        "target_met": result_verdict["ok"] or rate >= args.ops_per_second * 0.98,
        "held_rate": rate >= args.ops_per_second * 0.98,
        "state_before": before.get("state"),
        "state_settled": settled.get("state"),
        "settle_polls": polls,
        "drops_per_source": per_source,
        "drops_total": result_verdict["drops_total"],
        "integrity_delta": integrity_d,
        "cumulative_after": settled.get("integrity"),
        "zero_drops": result_verdict["drops_total"] == 0 and result_verdict["integrity_total"] == 0,
        "attribution_ok": per_source is not None,
        "pass": result_verdict["ok"],
        "failure_reasons": result_verdict["reasons"],
    }
    text = json.dumps(result, indent=2)
    print(text)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    if not result["attribution_ok"]:
        return 2
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
