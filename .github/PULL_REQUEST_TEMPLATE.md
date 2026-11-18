<!--
  AEGIS NIDS pull-request checklist (ROADMAP-086 tuning law + AGENTS.md
  patch discipline). Delete nothing below — check every box or explain
  why it does not apply. Reviewers: a PR that changes behavior without
  evidence is a reject, not a nitpick.
-->

## Slice declaration (AGENTS.md: one flow per patch)

- [ ] PATCH-ID:
- [ ] FLOW-ID / TARGET HEAD:
- [ ] IN-SCOPE / OUT-OF-SCOPE:
- [ ] CONTRACT IMPACT / ABI IMPACT / AUTHORITY IMPACT:

## Gates run (paste results, not claims)

- [ ] `zig build` + `zig build test` (incl. negative control for new tests)
- [ ] `cargo test` / `go test ./...` / `npm run test:all` (tiers touched)
- [ ] `python tools/truth.py verify` → TRUTH_VALID
- [ ] `python tools/release_engineering.py --verify` → match count:
- [ ] pytest subset (deselect only the known live-daemon pagination test)

## Behavior-change evidence (any unchecked box here blocks merge)

- [ ] No behavior change (docs/refactor/test-only), OR all below hold:
- [ ] Fail-closed default preserved (absent/unset config == old behavior)
- [ ] No new enforcement path; Rust PEP remains sole authority
- [ ] No silent drops: every refusal is counted, warned, or returned

## Tuning evidence (required iff any threshold/constant/timing changes)

- [ ] Dataset: source, duration, traffic mix, host class
- [ ] Before/after measurements (numbers, not adjectives)
- [ ] FP/FN counts on labeled data (benign baseline + attack validation)
- [ ] Safety floor respected: never below benign p99 without E5+ proof
- [ ] Evidence matrix updated (location):
- [ ] Rollback statement: previous values + conditions to revert

## Post-merge

- [ ] Truth artifacts rebased to final HEAD (`truth.py verify` green)
- [ ] UNWIRED_INVENTORY.md updated (closed gaps struck, new blockers filed)
