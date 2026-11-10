# SYSTEM-SURVEY-001 — addendum: post-survey status (2026-11-10)

Companion to `SYSTEM-SURVEY-001-20261110.md`. The survey was written before any
fix; this addendum records what changed afterwards and what did not. Nothing here
upgrades an evidence level: source and tooling changes are E2 until a host window
proves them.

| Finding | State after this session | Record |
|---|---|---|
| S2-04 KIND-ATTR root cause | **fixed in source** — `.custom` classified by provenance into the existing `fim_change` / `reg_change` / `etw_process_*` kinds; no wire change; `zig build test` green | `KIND-ATTR-001-20261110.md` |
| S1-02 digest gate | **fixed** — refresh refuses uncommitted tracked artifacts; bundle-layer binary hashing acknowledged; install-time driver copy byte-verified and aborts on mismatch | `GATE-HONESTY-001-20261110.md` |
| S1-03 evidence over-claim | **fixed for counts and markers** — evidence-only summary (E5 77, of which 27 carry an artifact), 50 `artifact_status: unrecorded`, 4 lab/historical markers, 1 broken pointer corrected; `head_sha` debt remains open | `GATE-HONESTY-001-20261110.md` |
| S1-04 control auth | **fixed in source** — `rules.reload` requires `.privileged`; table-wide invariant test; install-time `configs` ACL hardening; the live daemon still runs the old table until deployed | `CONTROL-AUTH-001-20261110.md` |
| S1-05 soak | **fixed** — fails on DEGRADED, loss, or SCM restart; the live run now correctly reports FAIL. `readiness` still refuses without naming a cause (open) | `GATE-HONESTY-001-20261110.md` |
| S1-01 driver mismatch | **mitigated in tooling** — copy is byte-verified and aborts; the host still runs `F63195B0…` until the host window replaces it | `ISSUE-30-ATTRIBUTION-20261110.md` §5.2 |
| S2-01 #30 | **diagnosed and explained** — the crashing image is the 2026-10-16 helper; the fix was never staged into `zig-out/bin`; staging gate added. Closure needs the host window | `ISSUE-30-ATTRIBUTION-20261110.md` |
| S2-02 driver start mode | **open** — needs the reboot decision in the host window | — |
| S2-03 inert injection detector | **fixed in source** — daemon no longer constructs the detector, `has_injection_detector` is false, the doc row says NOT WIRED, and `tests/security/test_capability_claims.py` fails if any of that reverts; the detector itself stays unwired | `INJECTION-CLAIM-001-20261110.md` |
| S2-05 two installers, two drivers | **fixed in source** — every packaging entry point now ships `build\x64\wfp\aegis_wfp.sys`, pinned by `tests/release/test_driver_packaging_sources.py`; the two installers still differ in verification strength | `DRIVER-PACKAGING-001-20261110.md` |
| S3-01 test writes tracked state | **fixed** — the test writes `tmp_path` and an autouse guard forbids the tracked paths | `TEST-HYGIENE-S301-20261110.md` |

## Corrections to the survey text

1. The control audit row **does** carry `caller_pid`
   (`handler_registry.zig:207-218`). S1-04 was an authorization gap, not an
   attribution gap.
2. Shipped binaries **do** get digests at the bundle layer:
   `tools/release_candidate.py:143-148` writes `SHA256SUMS` over every packaged
   file and `:213` verifies it. The missing control was *installed vs bundled*
   comparison — now enforced at install time for drivers, and at packaging time
   for native helpers (`tools/stage_helpers.py`).
3. `readiness` is not `{}`; it returns a full object that refuses
   (`ready:false`, `overall_gate:false`) while naming no cause
   (`degraded_components: []`, `failure_reasons: []`). The defect is "refuses
   without a reason", not "returns nothing".

## What is still required before any of this becomes E5

1. Host window: stop services, deploy `zig-out/bin` (or the rebuilt installer)
   with hash assertions, replace the WFP driver, restart, re-hash, record.
2. Reboot to close R-06 and FREEZE #22, after deciding the driver start model.
3. Start a **new** 24 h soak on the deployed build; only then is a PASS
   meaningful.
