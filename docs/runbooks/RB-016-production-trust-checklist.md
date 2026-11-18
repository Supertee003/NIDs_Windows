# RB-016: Production Trust Deployment Checklist

> Turning on the trust machinery the code already contains. Until every
> box below is checked, Ed25519 verification is observability, not a
> gate (unsigned policy loads and runs — by design, loudly).

## Objective

Move a deployment from default (unsigned policy loads, enforcement
escalates, brain accepts bare JSON) to attested (signed policy only,
authenticated brain channel, verified operator).

## Checklist

1. **Policy signing key**
   - Generate Ed25519 keypair OFFLINE. Never commit either half.
   - Write the public half (64-hex) to `configs/policy_trust.json`
     (live file, gitignored — see `configs/policy_trust.example.json`
     for shape; all-zero placeholder is rejected loudly).
     Fallback: `AEGIS_POLICY_PUBKEY` env (64-hex public key only).
   - Present-but-broken trust file does NOT fall back to env
     (`anchors_broken`) — fix the file, do not delete it to "recover".

2. **Sign the policy**
   - Seal `configs/policies.json` -> `configs/policies.sig.json`
     (sidecar over exact bytes; see RB-011 for the IR mirror workflow).
   - Verify read-only first: `python tools/aegisctl.py policy verify`
     must report top-level `verified:true`.

3. **Opt in to enforcement trust** (service environment):
   - Set `AEGIS_POLICY_ENFORCE_TRUSTED=1`.
   - Restart the service. Privileged actions on unsigned/unverifiable
     policy keep escalating exactly as before — that is the fail-closed
     posture, not an error.

4. **Brain channel secret** (only if the brain runs — see RB-017):
   - Set a >= 16-byte `AEGIS_BRAIN_SECRET` in BOTH the daemon and brain
     environments (never committed, never logged — both ends log
     posture, never the value).
   - Without it the channel is loopback-by-assumption with bare JSON:
     documented local-spoofable, acceptable only on single-operator
     hosts. HEALTH messages stay open either way.

5. **Confirm the gates** (read-only):
   - `enforce status`: `prevention_gate` + `host_effect_capable` reflect
     the intended posture (detection-only until steps 1-3 hold).
   - `enforce simulate --action block --severity 8`: honest projection
     (`outcome:allow` + `prevention_gate_closed` while closed).
   - Gitleaks policy (`.gitleaks.toml`) stays green — no new credential
     may land in history (publish gate, EVT-135).

## Verification

- `policy verify`: `verified:true` with envelope reason VALID.
- Unsigned/modified policy with the flag on: loads untrusted,
  privileged actions escalate (check `enforce status`).
- No secret material in `git status`, `git diff`, or the gitleaks scan.

## Rollback

Unset the flag, remove the trust file/sidecar, restart — the daemon
returns to default posture (loudly untrusted, never silently trusted).
Keep the keypair offline copy; rotation is re-issue + re-seal.

## Notes

- The legacy `AEGIS_RULES_HMAC_KEY` default label is dev-tooling only
  (warns loudly); it is NOT this gate. Do not confuse the two.
- `trust_store` mock module is never the verifier; canonical path is
  `policy_signing` (+ Rust agreement).

## References

- `src/policy/policy_signing.zig` (taxonomy, anchors, envelope),
  `src/daemon.zig` (trustOptIn), `src/policy/policy_ir.zig` (trusted flag).
- Brain MAC: `src/core/bridge_init.zig`, `brain/windows_brain.py`.
- Pins: G9/T7/BE-RCPT-091/CUSTODY-081 tests, `policy.verify` handler.
