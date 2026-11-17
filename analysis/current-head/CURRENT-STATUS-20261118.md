# CURRENT STATUS — 2026-11-18

## Identity

- **Records HEAD:** `ef728b3ae74ab9ab4dfc607181972c5bd310db1f`
- **Build source HEAD:** `b955f919122fa60480f83cb5b5c1be10b557f0cd`
- **Working branch:** `fix/stopline-truth-ci-signature-001`
- **Upstream delivery branch:** `codex/o2-etw-context`
- **Baseline branch:** `main` / `daf9088` (old baseline; not the release carrier)

These are intentionally different. A records-only commit does not change the build source under ADR-0008. The v2.0.0 closeout dated 2026-11-17 is historical evidence for its recorded source `7c604d5`; it is not evidence for this current source tree.

## Current gates

| Gate | Current state | Reason |
|---|---|---|
| Truth maps | PASS | `python tools/truth.py verify` uses source/build commit semantics |
| Python CI | OPEN until CI rerun | installer tests require native helpers to be built and staged |
| Release signature | OPEN until owner trust anchor is supplied | signature bytes must verify and public key must match `AEGIS_RELEASE_TRUSTED_PUBLIC_KEY` |
| Clean Windows E5 | Historical evidence only | current source has not been reinstalled/verified |
| Soak | OUT OF SCOPE for this patch | do not claim or rerun soak here |

## Fixes in this branch

1. CI builds and stages all three native helper DLLs before Python tests.
2. `final_audit.py` verifies Ed25519 signature bytes over the actual `SHA256SUMS` bytes and requires an owner-approved public-key trust anchor.
3. `AGENTS.md`, `AI_CONTEXT.md`, and this current-status record distinguish records HEAD from build source HEAD.

## GitHub review point

After the branch is pushed, review the branch and its CI run before merging. Do not merge to `main` automatically. Do not mark the release shippable until the owner supplies the trust anchor and current-source gates are rerun.
