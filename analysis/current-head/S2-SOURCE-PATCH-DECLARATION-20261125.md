# S2 source patch declaration — active control IPC nonce/replay

**TARGET HEAD:** `332fd4847571ab9f268b8448e1a05bf042915b26`
**BUILD SOURCE BEFORE PATCH:** `493648ff7bbee64851b58fcec09c19737c491393`

## PATCH DECLARATION

```
PATCH-ID:             S2-CONTROL-REPLAY-001
FLOW-ID:              Operator/CLI -> canonical aegis_control pipe -> v2 envelope validation
                      -> token authorization -> command handler -> audit
TARGET HEAD:          332fd48
TARGET FILES:         src/control/replay_guard.zig (new)
                      src/control/handler_registry.zig
                      src/all_tests.zig
                      tools/aegisctl/envelope.py (new)
                      tools/aegisctl/client.py
                      tools/aegisctl/utils.py
                      tools/aegisctl/api/control_api.py
                      tools/probe_control_pipe.py
                      tests/runtime/conftest.py
                      tests/security/test_control_replay_envelope.py (new)
                      shared/protocol/control_protocol.md
                      CONTRACT_MAP.json
TARGET SYMBOLS:       replay_guard.Guard.checkAndRecord; g_guard;
                      handler_registry.dispatch; build_v2_envelope; serialize_envelope;
                      build_v2_request; AegisClient.send/_send_pipe; control_request
IN-SCOPE:             enforce protocol_version == 2, 32-hex single-use nonce and
                      signed ±60 s issued_at_ms freshness in the ACTIVE Zig named-pipe
                      server; bounded 1024-entry process-local replay ring; audit
                      REPLAY_DENIED/STALE_REQUEST; one shared Python v2 envelope builder
                      used by every active probe/client; E2 contract tests
OUT-OF-SCOPE:         CanonicalEvent wire/rule/golden vector changes; role claims from
                      JSON; HMAC/key distribution; persisted cross-restart replay ledger;
                      enforcement/host-effect authority; release identity/signature;
                      elevated Windows E5 proof; other source gaps S3/S4
CONTRACT IMPACT:      CONTRACT-04 tightened: v2 envelope fields are now mandatory and
                      enforced at dispatch; active producers updated in the same patch
ABI IMPACT:           none — JSON fields already declared by protocol.v2; no FFI change
AUTHORITY IMPACT:     none — caller role remains token-derived; no host-effect authority
                      is created; replay guard is an admission check only
STATE IMPACT:         bounded process-local nonce ring; reset on daemon restart (stated
                      limitation); no persistent file state
TEST IMPACT:          Zig E2 unit tests (fresh cache) + Python E2 envelope/contract tests;
                      full pytest suite; production binary rebuild
EVIDENCE IMPACT:      E2 PASS for active-envelope enforcement; E3/E5 at rebuilt daemon
                      remain separate owner-run proof and are NOT claimed here
```

## OLD FLOW -> NEW FLOW

- OLD: the active v2 protocol declared `nonce` / `issued_at_ms`, and a test-only v1 module
  (`src/policy/control_ipc.zig`) implemented replay logic, but
  `handler_registry.dispatch()` read only `command`/`op` and `payload`. A captured
  authenticated request could be replayed verbatim.
- NEW: every v2 envelope must carry `protocol_version: 2`, a 32-hex `nonce` and an integer
  `issued_at_ms`. The server rejects stale/malformed/replayed requests before command
  dispatch, records rejections in the audit log, and all Python producers emit the exact
  same envelope through one builder.

## INVARIANT

- The named pipe ACL plus impersonated token remains the only caller-authentication
  authority; no JSON `role` or `caller_role` field is trusted.
- No `CanonicalEvent` field, rule ID, match pattern, policy hash stream or host-effect
  path changes.
- Replay state has a fixed memory ceiling and deterministic eviction; a restart reset is
  disclosed rather than silently treated as durable security.
- Rejection responses are valid JSON with an explicit `code` and `audit_id`.

## VERIFICATION GATE

1. `zig build test` (fresh cache) must include and pass the four replay-guard/envelope pins.
2. `python -m pytest tests/security/test_control_replay_envelope.py -q` must pass.
3. `zig build` must exit 0.
4. Full pytest must be run; unrelated host-dependent E6 failures stay OPEN and are not
   converted into S2 PASS.
5. Commit source plus declaration, rebaseline truth, add records/evidence, rerun all
   gates, then push.
