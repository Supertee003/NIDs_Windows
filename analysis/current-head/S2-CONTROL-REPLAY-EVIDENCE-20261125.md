# S2 evidence — active control IPC nonce/replay at build source `332fd48`

**PATCH-ID:** `S2-CONTROL-REPLAY-001`
**FLOW-ID:** operator/CLI -> canonical `aegis_control` pipe -> v2 envelope validation ->
token authorization -> command handler -> audit
**TARGET HEAD:** `332fd4847571ab9f268b8448e1a05bf042915b26`
**BUILD SOURCE AFTER PATCH:** `332fd48` (source patch; the records commit that follows
does not move the build source under ADR-0008)
**EVIDENCE LEVEL:** E2 (unit/contract proof only; no rebuilt-daemon E3 and no Windows E5
claim is made here)

## What changed

`src/control/handler_registry.zig::dispatch()` now requires every v2 envelope to carry
`protocol_version: 2`, a 32-hex `nonce`, and an integer `issued_at_ms` within a symmetric
60-second window. `src/control/replay_guard.zig` consumes each nonce once in a bounded
1024-entry ring with deterministic eviction and returns `ok | invalid_nonce | stale |
replay`. Rejections are audited as `ENVELOPE_REJECTED` with `STALE_REQUEST` or
`REPLAY_DENIED` and answered with valid JSON error envelopes. Caller role is still
derived from the impersonated Windows token; no JSON role is trusted.

`tools/aegisctl/envelope.py` is the single Python producer for these fields. The CLI
client, API client, control-pipe probe, runtime test probe and `control_request()` audit
path all use it; `control_request()` audits the exact wire envelope under
`requested_role` rather than claiming a JSON role authority.

## Verification performed

- `zig build --cache-dir D:\aegis-tmp\s2_zig_cache --global-cache-dir
  D:\aegis-tmp\s2_zig_global test` — exit 0; direct fresh-cache test binary:
  `2147 passed; 10 skipped; 0 failed`. Pins observed:
  - `control.handler_registry.test.CONTROL-REPLAY-001: error envelope is valid JSON with code and audit_id ... OK`
  - `control.replay_guard.test.replay guard: fresh nonce accepted, exact replay denied ... OK`
  - `control.replay_guard.test.replay guard: stale and malformed nonces fail closed ... OK`
  - `control.replay_guard.test.replay guard: ring eviction is bounded and deterministic ... OK`
- `python -m pytest tests/security/test_control_replay_envelope.py -q` — `5 passed`.
- `python -m pytest
  tests/security/test_t16_security_hardening.py::test_aegisctl_issues_request_envelope_for_privileged_actions
  tests/security/test_control_replay_envelope.py
  tests/runtime/test_aegisctl.py::TestAegisctlDiagnoseCommand -q` — `9 passed`
  after making the AC3 audit fields explicit in `utils.py`.
- Targeted contract/runtime regression group
  (`test_control_contract.py`, `test_aegisctl.py`, `test_control_retry.py`,
  `test_aegisctl_f2.py`, `test_contract_fixtures.py`) — `80 passed`.
- `python tools/aegisctl.py status --json` — the updated client parsed a live health
  response from the currently running daemon (which still hosts the previous server
  build; this proves client compatibility, NOT new-server replay enforcement).
- `zig build` — exit 0.

## Invariant / limits

- No CanonicalEvent field, rule, golden vector, policy hash, FFI ABI, authority or
  host-effect path changed.
- No HMAC/key material was introduced: the ACL and token impersonation remain the
  authentication authority; the nonce closes verbatim replay only.
- The replay ring is process-local. A daemon restart resets it; a durable ledger is
  explicitly out of scope and remains an open limitation.
- The active server binary was rebuilt but not swapped into the running production
  daemon in this slice. Exact replay denial on the live canonical pipe is therefore
  **NOT_PROVEN** at E3/E5 and requires the owner-run restart/probe runbook.
- Full suite at the S2 working tree: `5 failed, 1505 passed, 1 skipped,
  27 subtests passed`. One failure was S2-related
  (`test_t16_security_hardening.py` required literal `request_id`/`nonce` audit
  fields); it was fixed and its targeted rerun passed. The four remaining failures
  are the two known loopback-capture E6 tests plus two `aegisctl diagnose`
  10-second timeout/repo-root failures under full-suite load; both diagnose tests
  passed in the isolated rerun above. None is converted into an S2 PASS, and the
  full suite must be rerun at the final source after S3/S4.
