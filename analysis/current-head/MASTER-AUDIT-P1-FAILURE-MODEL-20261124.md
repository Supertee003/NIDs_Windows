# MASTER AUDIT — P1 carry-forward: FAILURE_MODEL backpressure table marked HISTORICAL (2026-11-24)

**TARGET HEAD:** `c7c1662bf1aea4474aaa7d7122032336d7df5d25` (records-only; build source stays `03bb86d`)
**STATUS:** PASS_E2 — documentation truth correction, no source/wire/rule/authority/host-effect/release change.

## FINDING

`docs/architecture/FAILURE_MODEL.md:3` declared **AUTHORITATIVE** while lines
191-202 described fill-percent tiers (`50-80% ELEVATED`, `80-95% HIGH` →
"Drop low-priority events", `>95% CRITICAL` → "Reject new events"). Current
`src/pipeline/event_queue.zig:220-299` has no occupancy levels and no
priority-drop branch. P1 recorded this as a carry-forward
(`MASTER-AUDIT-P1-20261124.md:69,77`); the user asked to finish all remaining
honest work.

## REPLACEMENT (records-only)

- Status line → `HISTORICAL in part — fail-soft model current; backpressure table superseded by src/pipeline/event_queue.zig (2026-11-24, P1 carry-forward)`.
- Backpressure section → current binary admission facts verified in source:
  `PIPELINE_QUEUE_SIZE=16384`, `WORKING_HOST_TAIL=14336`,
  `SOURCE_OCCUPANCY_CAP=7168`, `RESERVED_NETWORK_SLOTS=1024`,
  `CRITICAL_SLOTS=1024`, `MAX_PAYLOAD_BYTES=1500`; counters
  `g_queue_drops`, `g_reserved_tail_shed`, `g_source_quota_shed`;
  oversize payload truncated to a 1500-byte prefix with the wire claim kept
  verbatim. The former table is explicitly labelled HISTORICAL.

**INVARIANT:** no queue behavior, counter, rule, authority or wire change; only
the current-source description in a doc changed. No test or checker pinned the
old `AUTHORITATIVE` string (`tests/`, `scripts/`, `tools/` searched).

## VERIFICATION

```
python scripts/doc_checker.py                     -> 0 FAIL, 0 WARN
python scripts/check_summary.py                   -> SUMMARY_VALID
bad-link check                                    -> none
python tools/truth.py verify                      -> TRUTH_VALID @ 03bb86d
python tools/release_engineering.py --verify      -> 674/674 digests
```

## LIMITS / ROLLBACK / GATE

E2 documentation truth only. Not a new runtime measurement and not an E4/E5
claim. Release identity unchanged `v1.1` / `466a226` / `a53eda8`, 6/6 gates PASS
(0 open). Revert the records commit to restore the prior doc. **Completion gate:
PASS_E2** when doc/summary/link/truth/digest checks are green at unchanged build
source `03bb86d`.
