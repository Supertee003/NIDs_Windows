# VISIBILITY-001 — kernel-primary ingress with enforced Nose gating

**PATCH-ID:** VISIBILITY-001
**FLOW-ID:** CAPTURE-ARBITRATION, NET-INGRESS, QUEUE-STATS
**TARGET HEAD:** `f0baadf9205a69ea0fc3e27a26eb7968e71cbb40` (detached worktree)
**BUILD SOURCE BEFORE PATCH:** `f4cde3c503fd8b696183751a608b999768caa769`
**STATUS:** code + E2 COMPLETE. Not E5. No binary installed; running soak untouched.
**Owner decision applied:** "Enforce ก่อนเลือกโหมด" (2026-11-19). Blocker record
`VISIBILITY-001-BLOCKER-E1-20261119.md` is resolved by this patch.

---

## Declaration

- **TARGET FILES**
  - `src/capture/source_arbiter.zig` — `Mode.kernel_primary`, `Reason.kernel_primary`,
    `Input.kernel_primary`, `packetSubmissionAllowed`, `noseFrameIsShadowed`,
    `publishStartupMode`, name tables, 5 new tests
  - `src/capture/wfp_telemetry.zig` — `capturePrimaryKernelOptIn()` (public),
    `AEGIS_CAPTURE_PRIMARY=kernel` opt-in, 3 evaluation sites, split-supersede warning
  - `src/capture/nose_pipe_reader.zig` — submit-point guard + `g_nose_shadow_frames`
  - `src/daemon.zig` — `publishStartupMode()` before any capture thread spawn
  - `src/pipeline/runtime_state.zig` — `g_nose_shadow_frames`
  - `src/control/handler_registry.zig` — `wfp.nose_shadow_frames`, `kernel_owned` covers
    both kernel modes
  - `tools/aegisctl.py`, `tools/aegisctl/web_dashboard/app.py` — operator rendering
  - `docs/WFP_IOCTL_STATUS.md` — state table + enforcement semantics
  - `tests/wfp/test_capture_source_arbitration.py`,
    `tests/tools/test_aegisctl_queue.py` — contract pins
- **TARGET SYMBOLS:** as listed above.
- **IN-SCOPE:** acquisition ownership; visibility of shadowed rows on both sources;
  fail-open when the kernel provider is absent; operator opt-in switch.
- **OUT-OF-SCOPE:** enforcement/WFP block rules; policy; detection verdicts; driver
  rebuild; any host install/restart/topology change; the running soak host.
- **CONTRACT IMPACT:** additive only. `queue.stats.wfp` gains `nose_shadow_frames`;
  new mode name `kernel_primary` (ordinal 5, append-only). No wire/event layout change.
- **ABI IMPACT:** none. No struct layout, no canonical event change.
- **AUTHORITY IMPACT:** makes the existing authority claim enforceable: with
  `AEGIS_CAPTURE_PRIMARY=kernel` the WFP ring is the SOLE network ingress authority
  and Nose frames are drained + counted. Default remains `npcap_primary`.
- **STATE IMPACT:** one new atomic counter (`g_nose_shadow_frames`); `g_capture_mode`
  may now be published at startup instead of first telemetry evaluation.
- **TEST IMPACT:** 5 new Zig unit tests; 2 new Python contract/rendering tests;
  existing arbiter/CLI suites extended.
- **EVIDENCE IMPACT:** one new E2 evidence entry; blocker doc resolved.

---

## Result

PATCH-ID: VISIBILITY-001
FLOW-ID: CAPTURE-ARBITRATION, NET-INGRESS, QUEUE-STATS
TARGET HEAD: `f0baadf9205a69ea0fc3e27a26eb7968e71cbb40`
FINAL HEAD: unchanged (worktree, uncommitted — see TRUTH STATE)
FILES CHANGED: 13 source/docs/tests files (Slice 2 only; see git status for cumulative patch set)

OLD FLOW:
```
Nose pipe -> deserialize -> pushDecodedFrame -> detect
WFP ring  -> evaluate(arbiter) -> publish mode (LOG ONLY for packet side)
                               -> shadow_rows if kernel not allowed
packet_may_submit = advisory; enabling kernel-primary would duplicate authority
```

NEW FLOW:
```
daemon startup -> publishStartupMode(AEGIS_CAPTURE_PRIMARY=kernel)
WFP ring -> evaluate(arbiter with kernel_primary opt-in) -> publish mode
Nose pipe -> deserialize -> noseFrameIsShadowed(mode, provider_state)?
              yes -> g_nose_shadow_frames++ ; drain (continue) ; NOT submitted
              no  -> pushDecodedFrame -> detect
queue.stats.wfp -> mode / reason / shadow_rows / nose_shadow_frames / kernel_owned
aegisctl queue + web dashboard -> operator sees "operator opt-in; shadowed, not lost"
```

INVARIANT: exactly one network detection authority in every steady-state mode.
`undecided`, `npcap_primary`, `kernel_fallback`, `split_lab`, `none` and unknown
ordinals all permit Nose submission (byte-identical behaviour to before); only
`kernel_primary` + a live kernel provider denies it. Denied frames are counted,
never silently lost, and never reach the pipeline.

BUILD RESULT: `zig build` exit 0; `zig fmt` exit 0.

TEST RESULT (worktree, 2026-11-19):
```
zig all_tests        2114 passed / 11 skipped / 0 failed   (2125 total)
zig out-of-unit      1234 passed / 0 failed
pytest (wfp + aegisctl queue)  24 passed
VISIBILITY-001 Zig tests: 5/5 OK
  - kernel_primary opt-in shadows Nose, owns the kernel
  - kernel_primary without a kernel source fails open to Npcap
  - Nose shadowing also needs a live kernel provider
  - startup publication is active before capture threads spawn
  - only kernel_primary denies Nose submission
```
Prior Slice 1 suites re-run inside the 2125-test binary: all RULE-COVERAGE-001
tests still OK; C WFP helper suite unchanged at 6 cases PASS.

WINDOWS RESULT: not E5. `AEGIS_CAPTURE_PRIMARY=kernel` changes the running host
topology, so it is explicitly excluded while the existing soak is active. The
owner has approved a FRESH soak window for the new binary; no install, restart,
service mutation, topology switch or load injection has been performed. E5 must
observe: `mode=kernel_primary`, `nose_shadow_frames` advancing, `kernel_owned=true`,
zero duplicate event identities, and a fail-open probe with the provider absent.

EVIDENCE LEVEL: E2 (unit + contract) + E1 (static pin). Not E3/E5.

EVIDENCE ARTIFACTS:
- `analysis/current-head/VISIBILITY-001-PATCH.md`
- `analysis/current-head/VISIBILITY-001-BLOCKER-E1-20261119.md` (resolved)
- `analysis/current-head/WFP-RULE-SCOPE-20261119.md` (Slice 2 items 3-4)
- `docs/WFP_IOCTL_STATUS.md`
- `src/capture/source_arbiter.zig`, `src/capture/nose_pipe_reader.zig`

ROLLBACK: revert the 13 Slice 2 files. With the env var unset the runtime is
byte-identical to pre-patch (`publishStartupMode(false)` is a no-op and the
guard never fires), so rollback is safe even on a host that already has a
kernel-primary binary installed: simply unset `AEGIS_CAPTURE_PRIMARY`.

REMAINING RISK:
- E5 of the new binary is not done. A fresh soak window is owner-approved but
  not started (no new binary installed yet).
- WDK driver rebuild for the Slice 1 TCP-flags change remains pending.
- `kernel_primary` on a host with no WFP provider fails open to Nose; that is
  intentional, and must be asserted in E5 rather than assumed.
- The control-plane JSON is additive; a strict consumer that rejects unknown
  keys would need updating (no such consumer found in-repo).

OPEN BLOCKERS:
- Owner authorisation to commit the source patch (truth rebaseline is gated on it).
- Fresh 24 h soak window on the new binary with owner-approved baseline policy.
- WDK build + Windows host proof for Slice 1 driver changes.

COMPLETION GATE: Slice 2 COMPLETE at E2: permission enforced at the Nose submit
point with a visible counter, explicit opt-in, startup publication, provider
interlock, fail-open preserved, default posture unchanged. Board stays 5/6;
no tag, no publish, no host effect.

TRUTH STATE: `tools/truth.py verify` = TRUTH_INVALID in this worktree is CORRECT:
uncommitted source is never current truth. Maps stay stamped `f4cde3c`;
rebaseline only after the owner authorises the commit.
