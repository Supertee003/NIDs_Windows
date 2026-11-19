# Owner decision request — 4 gap-closure slices complete, await commit + fresh soak

**DATE:** 2026-11-19
**WORKTREE:** detached at `f0baadf9205a69ea0fc3e27a26eb7968e71cbb40` (dirty)
**BUILD SOURCE (per AGENTS.md):** `f4cde3c503fd8b696183751a608b999768caa769`
**SIGNED CANDIDATE ON HOST:** `release/T20-final/b597e71` — UNCHANGED, not rebuilt, not re-signed.

## What is done (all E2, no host effect, no wire change, no new authority)

| Slice | Patch | Result |
|---|---|---|
| 1 | `RULE-COVERAGE-001` | 23/23 rules catalog + evaluable; outbound WFP TCP flags → L4 matcher; FP-1 CLOSED-E5, FN-1 honestly OPEN. |
| 2 | `VISIBILITY-001` | Enforced kernel-primary at the Nose submit point; fail-open without provider; mode published pre-spawn; `g_nose_shadow_frames`; default stays `npcap_primary` (running soak byte-identical). |
| 3 | `OPERATOR-001` | Per-threat dashboard banner from daemon DEFCON; fail-closed policy verbs + retired notifier kept honest; `.privileged`/read-only-verify docs corrected. No egress, no new authority. |
| 4 | `OBSERVABILITY-001` | `shed_overload` + process generation in health; bounded Nose backpressure; bounded per-rule fire telemetry; latency item recorded STALE. CPU/RAM + FP counter deliberately not fabricated. |

**Evidence:** worktree `EVIDENCE_INDEX.json` 308 entries (E1 32 / E2 136). Four patch records + one WFP-scope doc + one STALE doc under `analysis/current-head/`.

**Verification:** `zig fmt` exit 0 · `zig build` exit 0 · `zig build test --summary all` 2116 passed / 11 skipped / 0 failed · full pytest 1402 passed / 35 skipped / 1 xfailed / 1 xpassed / 23 subtests · targeted suites 74 passed · pre-commit hygiene all clean. `tools/truth.py verify` = `TRUTH_INVALID` — EXPECTED while source is uncommitted (rebaseline is gated on the commit below).

## Decisions requested

1. **Commit authorisation.** Approve committing the 4-slice source patch from this worktree. This moves the build source HEAD off `f4cde3c` and requires a truth rebaseline (`tools/rebuild_truth.py`) afterwards. No push/tag/release.
2. **Records reconciliation.** The main tree has 5 records-only entries not present in the worktree index; the worktree adds 6 slice entries. A records commit in the main tree merges them into **313 entries (E1 37 / E2 136)**. Confirm this two-commit shape (source commit from worktree, records commit from main tree) is acceptable.
3. **New signed candidate.** A new binary must be built and signed with the owner trust anchor `txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o=`. Confirm who performs the signing / that the stored procedure may be used. I will not install or restart anything.
4. **Fresh soak window (already approved in principle).** It was NOT started: the binary it would measure would be obsolete after these slices. Start it only after the owner installs the new signed candidate and names the window. I will not install/restart/switch topology/inject load.
5. **Deferred items — accept as "closed by decision"?** Push notifier (STAY RETIRED), signed IR promotion (STAY verify-only), CPU/RAM gauges (deferred: native linkage + E5), FP counter (not fabricated: no runtime producer). Confirm, or ask for a future slice.
6. **Board / publish.** Board remains 5/6 (`soak_24h` OPEN) → `NOT SHIPPABLE`. Tag and GitHub Release remain blocked until soak PASS and a separate explicit owner confirmation. No action taken.

## Isolation proof

No install, no restart, no service change, no topology switch, no load injection, no edit to `release/T20-final/b597e71`, no edit to the saved soak baseline/delta artifacts, no egress, no external alert delivery. The running soak against `f4cde3c`/`b597e71` is untouched and still valid only for that candidate.
