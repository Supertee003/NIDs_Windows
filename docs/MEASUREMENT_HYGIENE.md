# Measurement Hygiene (operator discipline)

> Our own verification traffic is a load source. Four times this session
> an operator-side scan made the system look broken while it was healthy:
> full-ring `forensics verify` holding the ring mutex under 1100/s churn
> (queue drops + CLI timeouts), aggressive `--all` paging during soaks,
> and full-pytest live-daemon tests colliding on the single control-pipe
> instance. The instruments below keep verification honest.

## Rules

1. **Never measure during a soak.** Full `pytest tests/` runs live-daemon
   tests (forensic pagination, gate_d, e2e) that pound `forensics.list`
   and `verify`. Queue/rate/detection numbers taken in that window
   measure the test runner, not the system. Soaks and suites never overlap.
2. **One heavy scan at a time.** `forensics verify`, `--all` exports,
   and 64KB-max pages each hold shared resources (ring mutex seconds,
   pipe instance exclusively). Space them out; watch `depth` while
   scanning — if it climbs, the scan is the load.
3. **Budget pages are windows, not histories.** At ~1100 events/sec a
   200-record page covers ~0.2s and the 16k ring holds ~15s. A probe
   older than the window is invisible by construction — sample fast,
   in-process, and immediately, or use the daemon log
   (`C:\Windows\System32\logs\aegis_core.ndjson`, persistent, has
   timestamps and rule IDs) instead of the ring.
4. **Client retries cover milliseconds, not hogs.** `_query_daemon_retry`
   Backs off ~0.75s worst case. A query that needs longer (full verify
   under storm) fails honestly rather than queuing behind the hog.
   Daemon-side multi-instance is the deferred structural fix.
5. **Unknown is an answer.** `aegis_open.py` reports unknown (exit 2)
   instead of failing healthy systems or zeroing live counters when a
   query times out. A quiet `alerts` means "no matches in the scanned
   window", never "no attacks exist" — say which window.

## Quick reference (rates on this host)

| Load | Ring retention | 200-record page covers |
|---|---|---|
| ~300 ev/s (calm) | ~55s | ~0.7s |
| ~1100 ev/s (busy) | ~15s | ~0.2s |
| storm (3000+/s) | ~5s | unusable for probes |
