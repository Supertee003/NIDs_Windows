# RB-017: Brain (Tier-2) Bring-Up

> The brain is advisory-only and is **not** an SCM service and is never
> spawned by the daemon: algorithms and enforcement stay separated. On the
> current production host its supervisor is the scheduled task
> **AegisKeeper** (principal `SYSTEM`), which runs
> `pythonw.exe scripts/aegis_open.py keep` — a watchdog that converges
> service+nose+brain **every five minutes** (measured 2026-11-08). Its
> absence degrades analytics, never enforcement (block requests from the
> brain are stubbed FAILED and the PEP gate is fail-closed). `udp_brain:true`
> is sender-side only; the CLI `bridge` ownership check is the honest signal.
>
> Two measured traps, both fixed in this runbook's guidance:
> a **non-elevated** `schtasks /query /tn \AegisKeeper` is *access-denied*,
> which looks exactly like "no supervisor exists"; and the brain's HEALTH
> `out_events` counter used to be permanently 0 (never incremented), which
> looks exactly like "the return path is dead". Ask the daemon
> (`queue.stats` → `detection_brain`, forensic `python_brain`) before
> concluding either.

## Objective

Bring Tier-2 analytics up supervised: listener present, secret
provisioned, findings returning through the sensor pipe, health honest.

## Prerequisites

- Python 3.11+ with `pywin32` (named-pipe sensor returns).
- stdlib only otherwise (hashlib/hmac/json/socket/time) — no pip
  install needed.
- A `AEGIS_BRAIN_SECRET` value (>= 16 bytes, generated locally, never
  committed). Same value in daemon + brain environments.

## Steps

1. **Provision the secret** (both environments, never in files):
   daemon side and brain side `AEGIS_BRAIN_SECRET=<value>`.
   Without it the channel runs bare-JSON loopback-by-assumption
   (documented local-spoofable) — acceptable for a first smoke test,
   not for production (see RB-016 step 4).

2. **Start supervised** (foreground first, service later):
   ```
   python brain/windows_brain.py
   ```
   It binds UDP `127.0.0.1:9999`. Keep the console open for the first
   run; promote to a scheduled task / service wrapper only after step 4
   is green twice in a row.

   On this host the supervisor already exists: scheduled task
   **AegisKeeper** (`SYSTEM`) runs `pythonw scripts/aegis_open.py keep`,
   which converges service+nose+brain **every five minutes**. A killed
   brain therefore returns within one tick, not instantly — measured
   3 m 41 s (stopped 11:54:30, listener back 11:58:11 on 2026-11-08).
   Query the task **elevated**; non-elevated is access-denied, not absent.

3. **Confirm the listener** (the gap this runbook closes):
   ```
   python tools/aegisctl.py bridge
   ```
   Require the brain-channel endpoint to report a listener owned by
   the brain process (previously: `no listener`). `udp_brain:true`
   alone proves nothing — it is sender-side.

4. **Confirm the return path**: generate fixture traffic, then check
   the sensor pipe / forensic ring for `brain_tier2` provenance
   records carrying numeric rule identity. Findings arrive as advisory
   detection input (counted, correlated, never a host-effect claim).

   Measured recipe (2026-11-08, E5): with `AEGIS_BRAIN_SECRET` and
   `AEGIS_SENSOR_PIPE=1` provisioned, send one UDP datagram
   `<hmac-sha256 hex of body>.<body>` where body is
   `{"reason":"Forwarded: No Tier-1 Match","src_ip":"192.0.2.10","raw_payload":"A"*300}`
   (TEST-NET-1 keeps the always-deferred block request off real hosts)
   and confirm all three of:
   - `queue` → a `detection_brain` (ordinal 13) bucket with pushed+1;
   - `forensics.list source=5` → a `python_brain` record whose
     `rule_id` equals FNV-1a of the matched rule string
     (`CYTHON-003` → 2587872532), `verified: true`;
   - brain `HEALTH` → `out_events` +1 (only since 74d6ac2; before that
     the counter was never incremented and always read 0).

5. **Confirm posture logging**: both ends log MAC posture at startup
   (secret length class, never the value). Bare-JSON operation must be
   a conscious, recorded choice.

## Verification

- `bridge` shows the listener with the right owner process.
- `brain_tier2` records appear after fixture traffic.
- Daemon health flags unchanged (brain absence/presence never flips
  enforcement posture).
- Stopping the brain returns the `no listener` state with zero daemon
  errors (advisory loss is silent-safe, and now visible).

## Rollback

Stop the brain process/process group. Daemon continues detection-only;
delete the scheduled task if one was created. No daemon config changes
to revert (env-only).

## Notes

- Do NOT point the brain at a non-loopback channel: protocol, secrets,
  and supervision all assume localhost.
- The notifier script (`scripts/aegis_notifier.py`) is deprecated and
  unrelated — do not wire alerts through it for this proof.
- If Tier-2 is not needed, the formally accepted alternative is:
  leave it stopped and rely on the `bridge` no-listener signal.
  Record the decision either way.

## References

- Brain: `brain/windows_brain.py` (MAC matrix, stubbed enforcement).
- Daemon side: `src/core/bridge_init.zig` (sender, secret warn).
- Ownership diagnostic: `tools/aegisctl/api/control_api.py`
  (detect_foreign_udp_listener).
