# VISIBILITY-001 — Slice 2 blocker (E1, STOP-THE-LINE check)

**DATE:** 2026-11-19  
**WORKTREE HEAD:** `f0baadf9205a69ea0fc3e27a26eb7968e71cbb40`  
**STATUS:** **RESOLVED — 2026-11-19.** Owner chose option 1 ("enforce before
selecting the mode"). Implemented by `VISIBILITY-001-PATCH.md`: the arbiter gained
`Mode.kernel_primary`, the Nose submit-point now enforces the permission via
`noseFrameIsShadowed()` with a visible `g_nose_shadow_frames` counter, and the
mode is published before capture threads spawn. The finding below is retained
as the root-cause record; it is no longer an open blocker.

---

## Finding

The capture arbiter publishes a per-source submit permission, but only the
kernel side actually enforces it.

Evidence (current source at worktree HEAD):

| Site | Fact |
|---|---|
| `src/capture/source_arbiter.zig:73-78` | `Decision` carries `packet_may_submit` and `kernel_may_submit` |
| `src/capture/wfp_telemetry.zig:268` | kernel side enforces `if (!d.kernel_may_submit) { shadow_rows += 1 }` |
| `src/capture/wfp_telemetry.zig:179-184` | `d.packet_may_submit` is used **only in a log line** |
| `src/capture/nose_pipe_reader.zig:429` | Nose increments `g_nose_frames_submitted` and submits with **no** `g_capture_mode` check |
| repository-wide grep | `g_capture_mode` has exactly two writers (arbiter publish, test) and one reader (`queue.stats` rendering at `handler_registry.zig:806`) |

Consequence: adding an operator-selectable WFP-primary mode (the first Slice 2
item) while leaving the Nose path unguarded would let **both** sources submit
the same traffic. That is duplicate authority / duplicate event identity — an
AGENTS.md STOP-THE-LINE condition. It would also invalidate the arbiter's own
"one authority at a time" contract.

Note on current behaviour: the existing `kernel_fallback / nose_stalled` branch
deliberately sets both permissions true, so duplicates in that degraded mode are
a known, documented trade-off (accept duplicates rather than go blind). The
problem solved here is that the *field* reads as an enforced permission when it
is currently advisory on the Nose side.

---

## Options for the owner

1. **Enforce before selecting (recommended).** Add a `kernel_primary` mode plus
   a counted Nose-side guard at the frame-submit point, so a suppressed Nose
   frame is visible (`g_nose_shadow_frames`) instead of silently lost. Both
   capture topologies stay switchable. Default mode remains `npcap_primary`,
   so the running soak's behaviour is unchanged. Needs E2 gate + fresh E5 for
   any new binary.
2. **Keep WFP shadow-only for v1.1.** Implement Slice 2 items 3–4 only
   (document the ≤4096 B / no-reassembly and encrypted-payload boundaries as
   explicit rule-scope constraints); defer the topology change to v1.2.
3. **Different design** supplied by the owner (e.g. selection enforced in the
   Go Nose process rather than Zig).

No code was written for Slice 2 pending this decision. Slices 3 and 4 remain
unstarted; they also contain owner-level choices (notifier transport, rule
mutation authority, signed policy promotion).

---

## Related constraint

The owner-approved soak (`2026-11-19T04:38:09 → 2026-11-20T04:38:09`) is still
running against the installed `b597e71` candidate. Nothing in this worktree
installs, restarts, reconfigures topology, or injects load on that host.
