# RB-017: Brain (Tier-2) Bring-Up

> The brain is advisory-only and ships stopped: no SCM registration, no
> daemon spawn, no watchdog. Its absence degrades analytics, never
> enforcement (block requests from the brain are stubbed FAILED and the
> PEP gate is fail-closed). The live `udp_brain:true` health bit is
> sender-side only (socket created); the CLI `bridge` ownership check
> (`brain channel ... no listener`) is the honest signal today.

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
