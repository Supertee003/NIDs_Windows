# AEGIS Production Path

## Current position

The real observe-only sensor path is now proven for L4 Host-only transport, FIM, ETW, named-pipe ingress, and L7 payload capture. Rules-22 synthetic qualification is `22/22`. The prevention gate remains correctly closed.

## Remaining gates before production

| Gate | Required evidence | Status |
|---|---|---|
| Sensor readiness | Runtime healthy, FIM/ETW/Nose ready, forensic chain verified | PASS |
| Rule evidence | Each rule has fixture, source sensor, canonical event, `matched_rule_id`, expected action, and forensic linkage | PENDING |
| Detection parity | Python/Cython differential tests including truncation, NUL, invalid encoding, oversize, timeout, and fallback | PENDING |
| Policy authority | Rule validation, policy compile/sign/version/trust-store verification, TypeScript boundary tests | PARTIAL/PENDING |
| ABI/artifact freeze | Build manifest, hashes, Rust/Zig/C/Go ABI checks, clean rebuild | PENDING |
| Runtime lifecycle | Start/readiness, stop/join, restart, duplicate-owner and backpressure tests | PARTIAL |
| WFP controlled proof | Isolated reversible provider proof with exact filter receipt, read-back postcondition, cleanup, and recovery | PENDING; prevention stays closed |
| Release candidate | T20 audit/regression/golden-path reports, SBOM, checksums, rollback package verification | PENDING |
| Production cut-over | Signed artifacts, backup/rollback snapshot, staged rollout, monitoring, explicit gate opening | NOT STARTED |

## Cost-efficient execution order

1. Run the existing synthetic 22-rule qualification and save its artifacts.
2. Run static/contract suites only for Groups 3, 7, and 8; do not rerun already-passed sensor proofs.
3. Build a rule evidence matrix. Promote only rows with positive `matched_rule_id`; synthetic-only rows remain `QUALIFIED_SYNTHETIC`.
4. Run a clean rebuild and ABI/artifact manifest verification.
5. Run lifecycle/restart tests with prevention closed.
6. Assemble and verify the release candidate. Do not package as production if required T20 reports or driver artifacts are absent.
7. Design the isolated WFP receipt/postcondition proof. This is the only stage that can move a rule toward `BLOCK_PROVEN`.
8. Production cut-over requires a separate explicit approval after the exact release, rollback snapshot, and gate settings are displayed.

## Safety invariant

Until the controlled WFP proof has an exact receipt, provider read-back, postcondition, cleanup, and recovery evidence:

```text
prevention_gate = closed
host_effect = none/unconfirmed
legacy IP-only mutation = unavailable
```

## Efficient Host command bundle

Run from `D:\NIDs_Windows` and return only final summaries:

```powershell
python scripts\run_rules_22_safe.py
python -m pytest tests\cython tests\typescript tests\policy_signing -q
python tools\aegisctl.py health --json
python tools\release_candidate.py --verify
```

If a command fails, return the first failure block only; do not paste full logs.
